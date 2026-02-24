import { Rule, RuleMatch } from './types';

// Helper: find matches per line
function findMatches(regex: RegExp, code: string, lines: string[], confidence: number = 0.90): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  lines.forEach((line, index) => {
    for (const match of line.matchAll(globalRegex)) {
      matches.push({ line: index + 1, column: match.index, codeSnippet: line.trim(), confidence });
    }
  });
  return matches;
}

// ─── 1. User input directly into LLM messages ───────────────────────────────
const LLM_USER_INPUT_DIRECT: Rule = {
  id: 'LLM_USER_INPUT_DIRECT',
  cwe: 'CWE-20',
  owaspLLM: 'LLM01:2025',
  title: 'User input passed directly to LLM without sanitization',
  description: 'Passing unsanitized user-controlled input directly into LLM message payloads allows adversaries to inject arbitrary instructions, overriding intended model behavior. This enables prompt injection attacks that can leak data, bypass guardrails, or manipulate downstream actions.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Detect patterns like: content: req.body.message / content: userInput / messages: [{role:'user', content: req.body}]
      const hasLLMCall = /(messages|content|prompt)\s*[:=]/i.test(line) ||
        // Also detect agent/chain .run(user_input) patterns directly passing user data
        /\b(?:agent|executor|chain|crew|pipeline|llm)\.(run|invoke|arun|ainvoke|execute|kickoff|call|predict|generate)\s*\(\s*(?:user_input|userInput|user_message|req\.|request\.)/i.test(line);
      const hasUserInput = /(req\.body|req\.query|request\.body|request\.json|request\.get_json|input|userInput|user_input|userMessage|user_message|human_input|human_message|user_question|userQuery|user_query|user_prompt|userPrompt)\b/i.test(line);
      if (hasLLMCall && hasUserInput) {
        // Check if there's sanitization nearby
        const ctx = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 2)).join('\n');
        // Avoid false positive: "systemPrompt" in context is NOT a sanitization signal on its own
        const hasSanitize = /(sanitize|strip|escape|filter|validate|allowedTopics|reject|bleach\.|clean\()/i.test(ctx);
        if (!hasSanitize) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
        }
      }
    });
    return matches;
  },
};

// ─── 2. System prompt concatenated with user content ────────────────────────
const LLM_SYSTEM_PROMPT_INJECTION: Rule = {
  id: 'LLM_SYSTEM_PROMPT_INJECTION',
  cwe: 'CWE-77',
  owaspLLM: 'LLM01:2025',
  title: 'System prompt concatenated with user-controlled input',
  description: 'Concatenating user-supplied content into the system prompt allows an attacker to break out of the intended instruction boundary and inject malicious directives at the highest-trust role. This is a direct prompt injection vector that can fully subvert model behavior.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track variable names that hold system prompts
    const systemPromptVars = new Set<string>();
    // Track variable names that hold user input
    const userInputVars = new Set<string>();

    // ── Pre-pass: collect system-prompt vars and ALL function params ──────────
    // We collect ALL params of functions that contain LLM calls — any param
    // could be attacker-controlled (user question, docs, context, etc.)
    let inLLMFunction = false;
    lines.forEach((line) => {
      // Detect system-prompt variable assignments
      // Handles: system_prompt = """  /  systemPrompt = `  /  system_prompt = f"""
      const sysAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*[+]?=\s*(?:[fFrRbBuU]{0,2}"""|[fFrRbBuU]{0,2}'''|[fFrRbBuU]?'|[fFrRbBuU]?"|`|\()/);
      if (sysAssign && /(system|sys|prompt|SYSTEM|SYS)/i.test(sysAssign[1])) {
        systemPromptVars.add(sysAssign[1]);
      }

      // JS/TS variable from user input
      const userAssign = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:req\.|request\.|input|user)/i);
      if (userAssign) userInputVars.add(userAssign[1]);

      // Python function params — collect ALL params (any could be external data)
      const pyParam = line.match(/def\s+\w+\s*\(([^)]+)\)/);
      if (pyParam) {
        // Check if this function body contains an LLM call (look ahead up to 20 lines)
        inLLMFunction = true; // assume true, refine below with actual check
        pyParam[1].split(',').forEach(p => {
          const pname = p.trim().split(':')[0].trim().split('=')[0].trim();
          if (pname && pname !== 'self' && pname !== 'cls') {
            userInputVars.add(pname);
          }
        });
      }
    });

    // ── Main pass: detect injection patterns ─────────────────────────────────
    lines.forEach((line, index) => {
      // ── Pattern A: template literal (JS) with system role + user variable ──
      const hasSystemRole = /role\s*:\s*['"]system['"]|system_prompt\s*=|system\s*=\s*[`'"]/i.test(line);
      const hasTemplateLiteral = /`[^`]*(req\.|request\.|userInput|user_input|body\.|message)/i.test(line);

      // ── Pattern B: direct concat — (system_prompt|systemPrompt) += user... ──
      const hasDirectConcat = /(system_prompt|SYSTEM|systemPrompt)\s*[+]=?\s*(req\.|user|message|input)/i.test(line);

      // ── Pattern C: any line concatenating a known system-prompt var with a known user-input var ──
      //    e.g.  full_prompt = system_prompt + "\n" + user_input
      const hasIndirectConcat = (() => {
        if (!/\+/.test(line)) return false;
        const sysVarPresent = [...systemPromptVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
        const userVarPresent = [...userInputVars].some(v => new RegExp(`\\b${v}\\b`).test(line)) ||
          /(user_input|userInput|user_message|userMessage|req\.body|request\.json|request\.get_json)\b/i.test(line);
        return sysVarPresent && userVarPresent;
      })();

      // ── Pattern D: Python f-string assigned to a system prompt var ──────────
      // Handles both single-line and the opening line of multi-line f-strings.
      // A multi-line f-string:  system_prompt = f"""   ...{internal_docs}...  """
      // The opening line matches sysAssign + f-prefix; we then scan the body for {varname}.
      const hasFStringInjection = (() => {
        // Check if this line opens a system-prompt f-string assignment
        const opensFString = /(?:const|let|var|)\s*(\w+)\s*[+]?=\s*[fFrRbBuU]{1,2}["'`]/.test(line);
        if (!opensFString) return false;
        const varMatch = line.match(/(\w+)\s*[+]?=\s*[fFrRbBuU]{1,2}["'`]/);
        if (!varMatch || !/(system|sys|prompt|SYSTEM|SYS)/i.test(varMatch[1])) return false;

        // Scan the next 20 lines for {variable} interpolations
        const body = lines.slice(index, Math.min(lines.length, index + 20)).join('\n');
        // Look for {anyVar} where anyVar is a known user-input param or a generic external name
        const interpolatedVars = [...body.matchAll(/\{(\w+)\}/g)].map(m => m[1]);
        const hasUserVarInterpolated = interpolatedVars.some(v =>
          userInputVars.has(v) ||
          /(user|input|message|query|request|doc|context|data|content|text|prompt)\b/i.test(v)
        );
        return hasUserVarInterpolated;
      })();

      if ((hasSystemRole && hasTemplateLiteral) || hasDirectConcat || hasIndirectConcat || hasFStringInjection) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
      }

      // ── Pattern E: inside a multi-line f-string body, a line that interpolates a user param ──
      // Catches lines like:  {internal_docs}  or  {user_question}  when they appear inside a
      // system-prompt f-string, each representing a separate injection point.
      const isInsideFStringBody = (() => {
        // Check if any system-prompt f-string is "open" at this point
        // by scanning backwards for an unclosed f""" / f''' opening
        const precedingCode = lines.slice(0, index + 1).join('\n');
        // Find last f-string opening that matches a system prompt var
        const fstringOpenRe = /(\w+)\s*[+]?=\s*[fFrRbBuU]{1,2}("""|''')/g;
        let lastOpen: { varName: string; openIdx: number } | null = null;
        let m;
        const precedingLines = lines.slice(0, index);
        for (let i = 0; i < precedingLines.length; i++) {
          const mo = precedingLines[i].match(/(\w+)\s*[+]?=\s*[fFrRbBuU]{1,2}("""|''')/);
          if (mo && /(system|sys|prompt|SYSTEM|SYS)/i.test(mo[1])) {
            lastOpen = { varName: mo[1], openIdx: i };
          }
        }
        if (!lastOpen) return false;
        // Check the f-string hasn't closed yet (look for matching triple-quote between lastOpen and index)
        const between = lines.slice(lastOpen.openIdx + 1, index).join('\n');
        const closingQuote = lastOpen.openIdx >= 0 &&
          (lines[lastOpen.openIdx].includes('"""') ? between.includes('"""') : between.includes("'''"));
        if (closingQuote) return false;

        // We're inside the f-string. Check if this line has a {userVar} interpolation
        const lineInterp = [...line.matchAll(/\{(\w+)\}/g)].map(mm => mm[1]);
        return lineInterp.some(v =>
          (userInputVars.has(v) && v !== 'self' && v !== 'cls') ||
          /(user|input|message|query|request|doc|context|data|content|text)\b/i.test(v)
        );
      })();
      if (isInsideFStringBody && !matches.some(m => m.line === index + 1)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
      }
    });
    return matches;
  },
};

// ─── 3. LLM tool/function calling with user-controlled args ─────────────────
const LLM_TOOL_INPUT_INJECTION: Rule = {
  id: 'LLM_TOOL_INPUT_INJECTION',
  cwe: 'CWE-20',
  owaspLLM: 'LLM01:2025',
  title: 'LLM tool/function arguments sourced from user input',
  description: 'Allowing user-controlled data to populate LLM tool-call arguments enables an attacker to manipulate which tools are invoked and with what parameters. This can result in unauthorized actions such as data deletion, exfiltration, or execution of privileged operations.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Tool calls where user input feeds tool arguments
      const hasToolCall = /(tool_choice|function_call|tool_calls|tools)\s*[:=]/i.test(line);
      const hasUserData = /(req\.body|request\.body|userInput|user_input|args\s*=\s*req|parameters.*req\.)/i.test(line);
      if (hasToolCall && hasUserData) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.78 });
      }
    });
    return matches;
  },
};

// ─── 4. Unguarded LLM API calls (no input length / content check) ───────────
const LLM_NO_INPUT_GUARD: Rule = {
  id: 'LLM_NO_INPUT_GUARD',
  cwe: 'CWE-20',
  owaspLLM: 'LLM01:2025',
  title: 'LLM API call with no input length or content validation',
  description: 'LLM API calls that accept unbounded or unvalidated input are susceptible to prompt injection, denial-of-service via token exhaustion, and cost amplification attacks. Input validation is a critical first line of defense before content reaches the model.',
  severity: 'MEDIUM',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const isLLMCall = /(openai|anthropic|gemini|cohere|mistral|ollama|bedrock)\.(chat|messages|generate|complete)/i.test(line) ||
        /completions\.create|messages\.create|generate_content|chat\.complete/i.test(line) ||
        // Python OpenAI/Anthropic SDK: client.chat.completions.create / client.messages.create
        /client\.(chat\.completions|messages|completions|generate)\.create\s*\(/i.test(line) ||
        // Python generic: openai.ChatCompletion.create / openai.Completion.create
        /openai\.(ChatCompletion|Completion|chat)\.(create|acreate)\s*\(/i.test(line) ||
        // LangChain / AutoGen / CrewAI style: agent.run / chain.invoke / executor.run
        /\b(?:agent|executor|chain|crew|pipeline|llm)\.(run|invoke|arun|ainvoke|execute|kickoff|call|predict|generate)\s*\(/i.test(line);
      if (isLLMCall) {
        // Look for any input validation in surrounding 10 lines
        const ctx = lines.slice(Math.max(0, index - 10), Math.min(lines.length, index + 2)).join('\n');
        const hasValidation = /(\.length\s*[><!]|maxLength|max_length|trim\(\)|slice\(|substring|sanitize|validate)/i.test(ctx);
        if (!hasValidation) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.65 });
        }
      }
    });
    return matches;
  },
};

// ─── 5. LLM response fed directly into eval/exec/DB ────────────────────────
const LLM_OUTPUT_EXEC: Rule = {
  id: 'LLM_OUTPUT_EXEC',
  cwe: 'CWE-78',
  owaspLLM: 'LLM02:2025',
  title: 'LLM response executed directly as code or used in DB query',
  description: 'Executing LLM-generated output as code or using it in database queries without validation conflates untrusted model output with privileged execution context. An attacker who influences the model output can achieve remote code execution or SQL injection.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Look for variable names that look like LLM responses being eval'd / exec'd
    const llmResponseVars = /(completion|response|result|output|llmResult|aiResponse|gptResponse)\.(content|text|choices\[0\]|message\.content)/i;
    // Then used in exec/eval/query within 5 lines
    let lastLLMVar = '';
    lines.forEach((line, index) => {
      if (llmResponseVars.test(line)) {
        lastLLMVar = line.match(/(?:const|let|var)\s+(\w+)/i)?.[1] || '';
      }
      if (lastLLMVar && /(eval\(|exec\(|subprocess|child_process|db\.query|\.execute\s*\()/i.test(line)) {
        const withinRange = index < lines.findIndex((l, i) => i > index - 5 && llmResponseVars.test(l)) + 5;
        if (withinRange || new RegExp(lastLLMVar).test(line)) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
          lastLLMVar = '';
        }
      }
    });
    return matches;
  },
};

// ─── 6. Missing LLM output validation before acting on structured data ───────
const LLM_STRUCTURED_OUTPUT_UNVALIDATED: Rule = {
  id: 'LLM_STRUCTURED_OUTPUT_UNVALIDATED',
  cwe: 'CWE-20',
  owaspLLM: 'LLM02:2025',
  title: 'LLM JSON/structured output used without schema validation',
  description: 'Parsing and acting on LLM-generated structured data without schema validation can lead to unexpected field injection, type coercion attacks, or exploitation of downstream logic that assumes well-formed output. LLMs are non-deterministic and may produce malformed or adversarially crafted structures.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // JSON.parse on LLM output with no try/catch or schema check
      const hasParse = /JSON\.parse\s*\(|json\.loads\s*\(/i.test(line);
      const hasLLMContext = /(completion|response|message\.content|choices\[|output)/i.test(line);
      if (hasParse && hasLLMContext) {
        const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 5)).join('\n');
        const hasValidation = /(\.parse\s*\(parsed|zod|joi|yup|schema|validate|safeParse|assert)/i.test(ctx);
        if (!hasValidation) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }
    });
    return matches;
  },
};

// ─── 7. RAG / retrieval pipeline: external content injected into prompt ────────
// Indirect prompt injection: attacker plants instructions in documents that are
// fetched by the RAG pipeline and fed unsanitized into the LLM prompt.
// The model may treat retrieved text as trusted instructions (role confusion).
const RAG_UNSANITIZED_RETRIEVAL: Rule = {
  id: 'RAG_UNSANITIZED_RETRIEVAL',
  cwe: 'CWE-20',
  owaspLLM: 'LLM08:2025',
  title: 'Retrieved external content injected into LLM prompt without sanitization — indirect prompt injection risk',
  description: 'Injecting unsanitized content retrieved from external sources (e.g., web pages, documents, vector databases) into LLM prompts exposes the application to indirect prompt injection. An attacker can embed malicious instructions in retrieved content that the model interprets as trusted directives.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Step 1: Identify variables that hold retrieved/external content
    // e.g. chunks = retrieve(...) / results = search(...) / docs = vectordb.query(...)
    const retrievedVars = new Set<string>();

    lines.forEach((line) => {
      // Direct retrieval call assignment
      // e.g. chunks = retrieve(query)  /  results = search_index(q)  /  docs = db.similarity_search(...)
      const retrievalAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:\w+\.)*(retrieve|search|fetch|query|lookup|find|get_docs?|get_chunks?|similarity_search|semantic_search|vector_search|embed_search|knn_search)\s*\(/i
      );
      if (retrievalAssign) retrievedVars.add(retrievalAssign[1]);

      // Variables that aggregate/join retrieved chunks
      // e.g. context_block = "\n".join(...chunks)  /  context = "\n\n".join(doc.text for doc in docs)
      const joinAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(?:['"]\s*['"]\.join|\\n['"]\s*\.join|\s*join\s*\()/i);
      if (joinAssign) {
        const ctx5 = line;
        const anyRetrievedVarInLine = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(ctx5));
        if (anyRetrievedVarInLine) retrievedVars.add(joinAssign[1]);
      }

      // f-string / template joins
      // context_block = "\n\n".join(f"[SOURCE ...]...\n{c.text}" for c in chunks)
      const fJoinAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*["'`][^"'`]*["'`]\s*\.join\s*\(/i);
      if (fJoinAssign) {
        const lineAndNext = lines.slice(lines.indexOf(line), Math.min(lines.length, lines.indexOf(line) + 4)).join(' ');
        const anyRetrievedVarPresent = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(lineAndNext));
        if (anyRetrievedVarPresent) retrievedVars.add(fJoinAssign[1]);
      }

      // Explicit .text / .content / .page_content attribute access stored in a new var
      // e.g. doc_texts = [d.text for d in docs]
      const attrCollect = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*\[.*\.(text|content|page_content|body|chunk)\b/i);
      if (attrCollect) {
        const anyRetrievedInLine = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
        if (anyRetrievedInLine) retrievedVars.add(attrCollect[1]);
      }

      // render_context / format_context / build_context helpers called with retrieved vars
      const helperAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(?:render_context|format_context|build_context|format_docs|format_chunks|prepare_context)\s*\(/i);
      if (helperAssign) {
        const anyRetrievedInLine = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
        if (anyRetrievedInLine || retrievedVars.size > 0) retrievedVars.add(helperAssign[1]);
      }
    });

    // Step 2: Check if any retrieved/aggregated var is interpolated into a prompt without sanitization
    lines.forEach((line, index) => {
      if (retrievedVars.size === 0) return;

      // Check if this line opens a prompt-like f-string or template literal assignment
      const isPromptAssign = /(?:const|let|var|)\s*\w*(?:prompt|message|context|input|query)\w*\s*[+]?=\s*(?:[fFrRbBuU]{0,2}["'`]|\()/i.test(line) ||
        /content\s*[:=]\s*(?:[fFrRbBuU]{0,2}["'`]|\()/i.test(line);

      if (isPromptAssign) {
        // Scan the body of this assignment (up to 15 lines) for interpolated retrieved vars
        const body = lines.slice(index, Math.min(lines.length, index + 15)).join('\n');
        const interpolated = [...body.matchAll(/\{(\w+)(?:\.[^}]*)?\}/g)].map(m => m[1]);

        const hasRetrievedVarInterpolated = interpolated.some(v => retrievedVars.has(v));
        // Also check for direct string concat with retrieved var
        const hasRetrievedConcat = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(body) && /\+/.test(body));

        if (hasRetrievedVarInterpolated || hasRetrievedConcat) {
          // Check if there's any sanitization of the retrieved content before prompt injection
          const sanitizationCtx = lines.slice(Math.max(0, index - 15), index).join('\n');
          const hasSanitization = /(sanitize|strip_tags|clean|escape|bleach|DOMPurify|he\.encode|allowlist|denylist|re\.sub.*\[|\bfilter\b.*chunk|reject.*inject|guard.*prompt)/i.test(sanitizationCtx);

          if (!hasSanitization) {
            matches.push({
              line: index + 1,
              column: 0,
              codeSnippet: line.trim(),
              confidence: 0.88,
            });
          }
        }
      }

      // Also catch direct f-string on retrieved var's .text/.content attribute
      // e.g. f"Context: {chunk.text}" or f"{doc.page_content}"
      const directAttrInterp = /(f|F)["'][^"']*\{(\w+)\.(text|content|page_content|body|chunk)\}/.test(line);
      if (directAttrInterp) {
        const varMatch = line.match(/\{(\w+)\.(text|content|page_content|body|chunk)\}/);
        if (varMatch && retrievedVars.has(varMatch[1])) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
        }
      }
    });

    return matches;
  },
};

// ─── 8. Agent/Agentic loop: LLM-instructed tool calls executed without guard ──
// An attacker plants instructions in retrieved content or user messages that
// instruct the LLM/agent to call tools (send email, post to Slack, delete files)
// with arbitrary parameters. Without per-tool intent validation, the agent
// becomes a confused deputy executing attacker instructions.
const AGENT_TOOL_CALL_INJECTION: Rule = {
  id: 'AGENT_TOOL_CALL_INJECTION',
  cwe: 'CWE-441',
  owaspLLM: 'LLM06:2025',
  title: 'Agent executes tool calls based on LLM output without intent/allowlist guard',
  description: 'Autonomous agents that execute tool calls derived from LLM output without an intent-verification or allowlist guard are vulnerable to confused deputy attacks. An attacker can plant instructions in user messages or retrieved content that cause the agent to invoke privileged tools with attacker-controlled arguments.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track variables that hold LLM / agent outputs
    const llmOutputVars = new Set<string>();
    // Track tool/function definitions that look like side-effectful operations
    const toolFuncNames = new Set<string>();

    // Pre-pass: identify LLM output vars and tool function names
    lines.forEach((line) => {
      // LLM response vars
      // e.g. response = client.chat.completions.create(...)
      //      result = openai.chat.completions.create(...)
      //      output = agent.run(...)
      const llmAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:client|openai|anthropic|agent|llm|model|chain)\.(chat|messages|completions|run|invoke|call|generate|predict|arun|ainvoke)/i);
      if (llmAssign) llmOutputVars.add(llmAssign[1]);

      // Side-effectful tool function definitions
      // e.g. def send_slack(...), def send_email(...), def delete_file(...), def post_to(...)
      const toolFunc = line.match(/def\s+(send|post|delete|remove|create|update|write|execute|run|call|invoke|email|slack|webhook|notify|upload|download|deploy|transfer)\w*\s*\(/i);
      if (toolFunc) toolFuncNames.add(toolFunc[1]);

      // JS/TS arrow functions or regular functions
      const jsFuncDef = line.match(/(?:const|let|var|function)\s+(send|post|delete|remove|create|update|write|execute|run|call|invoke|email|slack|webhook|notify|upload|download|deploy|transfer)\w*\s*(?:=\s*(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>|\()/i);
      if (jsFuncDef) toolFuncNames.add(jsFuncDef[1]);
    });

    // Main pass: detect unguarded agent tool execution patterns
    lines.forEach((line, index) => {
      const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 3)).join('\n');

      // Pattern A: direct call to side-effectful tool with retrieved/LLM output variable
      // e.g. slack_send(channel, context)  or  send_email(to, llm_response)
      const hasSideEffectCall = /\b(send|post|delete|remove|write|execute|deploy|transfer|upload|email|slack|webhook)\w*\s*\(/i.test(line);
      if (hasSideEffectCall) {
        // Check if a retrieved/LLM var or retrieved content keyword is in the args
        const hasLLMOrRetrievedArg = [...llmOutputVars].some(v => new RegExp(`\\b${v}\\b`).test(line)) ||
          /(context|chunk|retriev|doc|content|response|result|output)\b/i.test(line);

        if (hasLLMOrRetrievedArg) {
          // Look for intent/allowlist guard in surrounding context
          const hasGuard = /(allowed_tools|allowlist|whitelist|intent|classify|check_permission|require_confirmation|user_approved|guard|gate|policy)/i.test(ctx);
          if (!hasGuard) {
            matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.82 });
          }
        }
      }

      // Pattern B: executing tool_calls from LLM response without validation
      // e.g. for tool_call in response.tool_calls: execute(tool_call)
      //      tool_result = run_tool(response["tool_calls"][0])
      const hasToolCallExec = /(tool_calls|function_call|tool_call)\b.*\b(execute|run|call|invoke|dispatch)/i.test(line) ||
        /(execute|run|call|invoke|dispatch)\s*\(.*\b(tool_calls?|function_call)\b/i.test(line);
      if (hasToolCallExec) {
        const hasValidation = /(validate|whitelist|allowlist|allowed_tools|schema|assert|check|guard|policy|approved)/i.test(ctx);
        if (!hasValidation) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
        }
      }

      // Pattern C: LangChain / AutoGen / CrewAI style: agent.run(user_input) with tools defined
      // These frameworks automatically execute tool calls from LLM output
      const hasAgentRun = /\b(?:agent|executor|chain|crew|pipeline)\.(run|invoke|arun|ainvoke|execute|kickoff)\s*\(/i.test(line);
      if (hasAgentRun) {
        // Check if tools are registered anywhere in the file (danger: auto-execution)
        const hasToolsDefined = /(tools\s*=|AgentExecutor|initialize_agent|Agent\(|@tool\b|tool\s*=\s*\[)/i.test(code);
        const hasInputGuard = /(validate|sanitize|allowlist|max_iterations|human_in_the_loop|confirmation)/i.test(ctx);
        if (hasToolsDefined && !hasInputGuard) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }
    });

    return matches;
  },
};

// ─── 9. LLM output reused as system prompt (prompt loop injection) ────────────
// When LLM output is fed back as the system prompt or injected into the next
// turn's system role, an attacker can manipulate prior output to control
// subsequent model behavior — a "prompt loop" or "memory poisoning" attack.
const LLM_OUTPUT_AS_SYSTEM_PROMPT: Rule = {
  id: 'LLM_OUTPUT_AS_SYSTEM_PROMPT',
  cwe: 'CWE-77',
  owaspLLM: 'LLM01:2025',
  title: 'LLM output reused as system prompt — prompt loop / memory poisoning risk',
  description: 'Feeding LLM-generated output back into the system prompt creates a trust boundary collapse where model output — potentially influenced by prior injection — gains system-level authority in subsequent turns. This enables memory poisoning and prompt loop attacks that persist across multi-turn conversations.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track vars assigned from LLM responses
    const llmOutputVars = new Set<string>();
    lines.forEach((line) => {
      // response = client.chat...  /  result = openai.chat...  /  output = llm.generate(...)
      const llmAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:client|openai|anthropic|llm|model|chain|agent)\.(chat|messages|completions|generate|predict|run|invoke)/i
      );
      if (llmAssign) llmOutputVars.add(llmAssign[1]);

      // Also track .content / .text extraction from LLM responses
      // next_prompt = response.choices[0].message.content
      const contentExtract = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*\w+\.(choices\[0\]\.message\.content|content|text|output|message)/i);
      if (contentExtract) {
        const sourceVar = line.match(/=\s*(\w+)\./)?.[1];
        if (sourceVar && llmOutputVars.has(sourceVar)) llmOutputVars.add(contentExtract[1]);
      }
    });

    // Detect LLM output being fed back into system role
    lines.forEach((line, index) => {
      // Pattern A: role: "system", content: <llm_output_var>
      const hasSystemRole = /role\s*:\s*['"]system['"]/.test(line);
      if (hasSystemRole) {
        const nearby = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 3)).join('\n');
        const hasLLMVarInSystem = [...llmOutputVars].some(v => new RegExp(`\\b${v}\\b`).test(nearby));
        if (hasLLMVarInSystem) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
        }
      }

      // Pattern B: system_prompt = <llm_output_var>  (reassignment from LLM output)
      const syspromptAssign = line.match(/(\w+)\s*=\s*(\w+)/);
      if (syspromptAssign) {
        const lhsIsSystem = /(system_prompt|systemPrompt|system_message|sysprompt)/i.test(syspromptAssign[1]);
        const rhsIsLLMOut = llmOutputVars.has(syspromptAssign[2]);
        if (lhsIsSystem && rhsIsLLMOut) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
        }
      }

      // Pattern C: memory/history array that feeds system messages
      // conversation_history.append({"role": "system", content: response_text})
      const appendToSystem = /\.(append|push|add)\s*\(.*role.*system.*content.*(?:response|output|result|completion)/i.test(line) ||
        /\.(append|push|add)\s*\(.*content.*(?:response|output|result|completion).*role.*system/i.test(line);
      if (appendToSystem) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
      }
    });

    return matches;
  },
};

// ─── 10. Jailbreak / prompt override pattern detection ────────────────────────
// Catches code that is explicitly designed around known jailbreak patterns:
// e.g. "DAN", "ignore previous instructions", role-play prompts that bypass
// guardrails, or code that checks for these patterns (implies they're a concern
// but still passes them through to the model).
// Also detects dynamic system prompt injection via user-controlled "persona" or "mode".
const LLM_JAILBREAK_PATTERN: Rule = {
  id: 'LLM_JAILBREAK_PATTERN',
  cwe: 'CWE-693',
  owaspLLM: 'LLM01:2025',
  title: 'Jailbreak / prompt override patterns detected in code or prompts',
  description: 'Jailbreak patterns such as "ignore previous instructions" or user-controlled persona injection attempt to override the model\'s safety guidelines and operational constraints. Their presence in source code or prompt templates indicates the application may be vulnerable to or actively facilitating prompt override attacks.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const lower = line.toLowerCase();

      // Pattern A: hardcoded jailbreak / override strings in system prompts or messages
      // These are in string literals → attacker-crafted content embedded in source
      const hasJailbreakString = /(["'`])(?:[^"'`]*)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|forget\s+(all\s+)?(previous|prior)\s+instructions?|disregard\s+.{0,40}rules?|you\s+are\s+now\s+(?:DAN|Jailbreak|EvilBot)|act\s+as\s+if\s+you\s+have\s+no\s+(restrictions?|guidelines?)|pretend\s+(you\s+are|to\s+be)\s+an?\s+AI\s+that)\1/i.test(line);
      if (hasJailbreakString) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.90 });
        return;
      }

      // Pattern B: code that allows user to set "persona", "mode", or "role" that
      // then gets injected into the system prompt without allowlist
      const hasPersonaInjection = (() => {
        // user-supplied "persona" or "mode" variable used in system prompt template
        const personaFromUser = /(persona|mode|role|personality|character)\s*=\s*(?:req\.|request\.|user_|input|params)/i.test(line);
        if (!personaFromUser) return false;
        // Check if that persona is later used in system prompt (within 15 lines)
        const ctx = lines.slice(index, Math.min(lines.length, index + 15)).join('\n');
        return /(system_prompt|systemPrompt|system\s*role|role.*system).*\{?(persona|mode|role|personality|character)\}?/i.test(ctx) ||
          /\{(persona|mode|role|personality|character)\}/i.test(ctx);
      })();
      if (hasPersonaInjection) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.82 });
      }

      // Pattern C: code checks for injection markers but still passes content through
      // (contains_injection_markers returns bool but result is not used to block)
      const checksButDoesntBlock = /contains_injection_markers?\s*\(([^)]+)\)/.test(line);
      if (checksButDoesntBlock) {
        // Look for an 'if' using this result within 3 lines
        const nextCtx = lines.slice(index, Math.min(lines.length, index + 4)).join('\n');
        const hasBlock = /if\s+(?:not\s+)?contains_injection_markers?|return\s+(?:False|None|error|raise)/i.test(nextCtx);
        if (!hasBlock) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }
    });

    return matches;
  },
};

// ─── 11. Multi-turn context injection (conversation history manipulation) ──────
// In multi-turn chat apps, user messages are stored in a history array and fed
// back to the model. If the history is loaded from an untrusted source (DB, file,
// URL param) without validation, an attacker can pre-seed malicious "assistant"
// messages or fabricate system messages in the history.
const LLM_HISTORY_INJECTION: Rule = {
  id: 'LLM_HISTORY_INJECTION',
  cwe: 'CWE-20',
  owaspLLM: 'LLM01:2025',
  title: 'Conversation history loaded from untrusted source without validation',
  description: 'Loading conversation history from untrusted external sources (database, request body, file) without validating role integrity allows an attacker to pre-seed fabricated assistant or system messages. This manipulates the model\'s context and can bypass safety measures or extract sensitive information.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Pattern A: history loaded from DB / file / request body and directly spread into messages
      const hasHistoryLoad = /(history|conversation|chat_history|messages|thread)\s*=\s*(?:await\s+)?(?:db\.|redis\.|cache\.|req\.|request\.|json\.load|open\(|readFile|localStorage|sessionStorage)/i.test(line);
      if (hasHistoryLoad) {
        // Check if there's validation of the loaded history
        const ctx = lines.slice(index, Math.min(lines.length, index + 10)).join('\n');
        const hasValidation = /(validate|schema|assert|filter|sanitize|allowedRoles?|check_role|zod|joi|pydantic)/i.test(ctx);
        if (!hasValidation) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.78 });
        }
      }

      // Pattern B: spreading unvalidated history directly into LLM messages array
      // messages: [...history, { role: "user", content: userInput }]
      // Also catches: messages: [...messages, {role:"user",...}] — spreading self/prior unvalidated messages
      const hasHistorySpread = /messages\s*[:=]\s*\[\s*\.{3}(history|conversation|messages|chat_history|thread)/i.test(line) ||
        /messages\s*[:=]\s*\[.*\*\s*(history|conversation|messages|chat_history)/i.test(line);
      if (hasHistorySpread) {
        const ctx = lines.slice(Math.max(0, index - 5), index).join('\n');
        const hasValidation = /(validate|filter|sanitize|allowedRoles?|schema)/i.test(ctx);
        if (!hasValidation) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
        }
      }

      // Pattern C: messages array passed directly to LLM without filtering
      // e.g. model: "gpt-4", messages  — where messages came from a parameter or external source
      const hasMsgParam = /\bmodel\s*:\s*["'][^"']+["']/.test(line);
      if (hasMsgParam) {
        // Look up to see if 'messages' was passed in as a function param (not locally constructed)
        const nearby = lines.slice(Math.max(0, index - 10), index + 3).join('\n');
        const messagesIsParam = /function\s+\w+\s*\([^)]*\bmessages\b/i.test(nearby) ||
          /def\s+\w+\s*\([^)]*\bmessages\b/i.test(nearby) ||
          /=>\s*\{/.test(nearby) && /\bmessages\b/.test(lines.slice(Math.max(0, index - 5), index).join('\n'));
        if (messagesIsParam) {
          const hasValidation = /(validate|filter|sanitize|allowedRoles?|schema)/i.test(nearby);
          if (!hasValidation) {
            matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
          }
        }
      }
    });

    return matches;
  },
};

// ─── 12. Prompt leaking — system prompt revealed to user ──────────────────────
// Code that echoes, logs, or returns the system prompt to the user/client,
// or that processes a request to "reveal your instructions" without blocking it.
const LLM_PROMPT_LEAK: Rule = {
  id: 'LLM_PROMPT_LEAK',
  cwe: 'CWE-200',
  owaspLLM: 'LLM07:2025',
  title: 'System prompt may be leaked to users via response or logs',
  description: 'Exposing the system prompt to end users via API responses or log output reveals proprietary instructions, safety guardrails, and architectural details that an attacker can exploit to craft more precise injection payloads. System prompts should be treated as sensitive configuration and never returned to clients.',
  severity: 'MEDIUM',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    const systemPromptVars = new Set<string>();
    lines.forEach((line) => {
      const sysAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*[+]?=\s*(?:[fFrRbBuU]{0,2}["'`])/);
      if (sysAssign && /(system_prompt|systemPrompt|system_message|SYSTEM_PROMPT)/i.test(sysAssign[1])) {
        systemPromptVars.add(sysAssign[1]);
      }
    });

    lines.forEach((line, index) => {
      // Pattern A: system prompt variable returned in response or logged
      const hasSysVarInOutput = [...systemPromptVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
      if (hasSysVarInOutput) {
        const isOutput = /(res\.json|res\.send|return|print\(|logger\.|console\.|json\.dumps|response\.json)/i.test(line);
        if (isOutput) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }

      // Pattern B: code that explicitly includes "reveal" / "print" / "show" of instructions
      // when asked — no guard
      const revealsPrompt = /(reveal|show|print|return|disclose|expose)\s+.{0,30}(system\s*prompt|instructions?|system\s*message)/i.test(line);
      if (revealsPrompt) {
        const ctx = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 2)).join('\n');
        const hasGuard = /(forbidden|not\s+allowed|reject|block|raise|return\s+(?:False|None|error))/i.test(ctx);
        if (!hasGuard) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
        }
      }
    });

    return matches;
  },
};

// ─── 13. Data exfiltration via LLM tool calls ────────────────────────────────
// Attacker plants a retrieval document that instructs the LLM to call an
// outbound tool (send_to_webhook, http_request, email, etc.) with sensitive
// context. This is a specific sub-pattern of agent injection targeting
// data exfiltration rather than command execution.
const LLM_DATA_EXFILTRATION_TOOL: Rule = {
  id: 'LLM_DATA_EXFILTRATION_TOOL',
  cwe: 'CWE-441',
  owaspLLM: 'LLM06:2025',
  title: 'Sensitive data sent to external endpoint via LLM-driven tool call — exfiltration risk',
  description: 'An LLM agent that can invoke outbound HTTP or messaging tools without user-intent verification can be manipulated into exfiltrating sensitive context data to attacker-controlled endpoints. This is a high-impact variant of indirect prompt injection targeting data exfiltration at the infrastructure level.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Look for code where retrieved/LLM-output content is passed to outbound HTTP / messaging calls
    const retrievedVars = new Set<string>();
    const llmOutputVars = new Set<string>();

    lines.forEach((line) => {
      const retrievalAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:\w+\.)*(retrieve|search|fetch|query|render_context|format_context|build_context)\s*\(/i
      );
      if (retrievalAssign) retrievedVars.add(retrievalAssign[1]);

      const llmAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:client|openai|anthropic|llm|model)\.(chat|messages|completions|generate)/i
      );
      if (llmAssign) llmOutputVars.add(llmAssign[1]);

      // join/render helpers
      const fJoinAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*["'`][^"'`]*["'`]\s*\.join\s*\(/i);
      if (fJoinAssign) {
        const anyRetrieved = [...retrievedVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
        if (anyRetrieved) retrievedVars.add(fJoinAssign[1]);
      }

      const helperAssign = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(?:render_context|format_context|build_context|format_docs)\s*\(/i);
      if (helperAssign) retrievedVars.add(helperAssign[1]);
    });

    lines.forEach((line, index) => {
      // Outbound calls: HTTP requests, webhooks, email, Slack
      const isOutboundCall = /(requests\.(get|post|put|patch)|fetch\(|axios\.(get|post)|http\.request|urllib|httpx\.|send_email|send_message|post_to|webhook|slack_send|slack\.post|sendgrid|smtp)/i.test(line);

      if (isOutboundCall) {
        // Check if retrieved or LLM output is in the args
        const hasRetrievedInArgs = [...retrievedVars, ...llmOutputVars].some(v => new RegExp(`\\b${v}\\b`).test(line));
        const hasContentKeyword = /(context|chunk|retrieved|document|response|result|output|completion)\b/i.test(line);

        if (hasRetrievedInArgs || hasContentKeyword) {
          // Look for an explicit user-intent guard
          const ctx = lines.slice(Math.max(0, index - 8), Math.min(lines.length, index + 2)).join('\n');
          const hasGuard = /(user_approved|confirmed|intent|allowed_tools|whitelist|allowlist|check_permission|require_confirmation|guard)/i.test(ctx);
          if (!hasGuard) {
            matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.83 });
          }
        }
      }
    });

    return matches;
  },
};

// ─── 14. Missing token limit on LLM API call ─────────────────────────────────
// LLM04:2025 / LLM10:2025 — Unbounded token output = unbounded cost and potential DoS.
// Without max_tokens, a single adversarial prompt can consume tens of thousands of tokens.
const LLM_TOKEN_LIMIT_MISSING: Rule = {
  id: 'LLM_TOKEN_LIMIT_MISSING',
  owaspLLM: 'LLM04:2025',
  title: 'LLM API call missing max_tokens — unbounded cost and DoS risk',
  description: 'An LLM API call without a max_tokens (or equivalent) limit allows adversarially crafted prompts to generate arbitrarily long responses, exhausting your API budget or causing service degradation. Always set an explicit token ceiling to bound cost and latency.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const llmCallRegex = /(openai|anthropic|gemini|cohere|mistral)\.(chat|messages|generate|complete|completions)/i;
    const sdkCallRegex = /(completions\.create|messages\.create|generate_content|chat\.complete|client\.(chat\.completions|messages|completions)\.create)\s*\(/i;
    const tokenLimitRegex = /(max_tokens|maxTokens|max_output_tokens|max_completion_tokens)\s*[=:]/i;

    lines.forEach((line, index) => {
      const isLLMCall = llmCallRegex.test(line) || sdkCallRegex.test(line);
      if (!isLLMCall) return;

      // Check ±10 lines for a token limit setting
      const ctx = lines.slice(Math.max(0, index - 10), Math.min(lines.length, index + 10)).join('\n');
      if (!tokenLimitRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
      }
    });
    return matches;
  },
};

// ─── 15. Missing timeout on LLM API call ──────────────────────────────────────
// LLM04:2025 — Without a timeout, a stalled LLM request can hang indefinitely,
// blocking worker threads and enabling a slow-loris style DoS against your own backend.
const LLM_NO_TIMEOUT: Rule = {
  id: 'LLM_NO_TIMEOUT',
  owaspLLM: 'LLM04:2025',
  title: 'LLM API call has no timeout — hanging request / resource exhaustion risk',
  description: 'LLM API calls without a timeout or AbortSignal can hang indefinitely if the upstream provider is slow or unresponsive. This can exhaust connection pools, block event loop threads, and make your application appear down to users. Always set a hard timeout on LLM requests.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const llmCallRegex = /(openai|anthropic|gemini|cohere|mistral)\.(chat|messages|generate|complete|completions)/i;
    const sdkCallRegex = /(completions\.create|messages\.create|generate_content|chat\.complete|client\.(chat\.completions|messages|completions)\.create)\s*\(/i;
    const timeoutRegex = /(timeout|AbortSignal|AbortController|signal\s*[=:]|time_limit|httpx_args.*timeout)/i;

    lines.forEach((line, index) => {
      const isLLMCall = llmCallRegex.test(line) || sdkCallRegex.test(line);
      if (!isLLMCall) return;

      const ctx = lines.slice(Math.max(0, index - 10), Math.min(lines.length, index + 10)).join('\n');
      if (!timeoutRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
      }
    });
    return matches;
  },
};

// ─── 16. LLM endpoint missing rate limiting ────────────────────────────────────
// LLM10:2025 — An API route that calls an LLM with no rate limiting allows any user
// to trigger unlimited expensive model calls, rapidly exhausting your API budget.
const LLM_RATE_LIMIT_MISSING: Rule = {
  id: 'LLM_RATE_LIMIT_MISSING',
  owaspLLM: 'LLM10:2025',
  title: 'LLM API endpoint has no rate limiting — budget exhaustion risk',
  description: 'An HTTP endpoint that triggers LLM API calls without any rate limiting allows malicious or misconfigured clients to flood the endpoint with requests, rapidly burning through your API credits. Implement per-IP or per-user rate limiting on any endpoint that invokes a paid LLM API.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const routeRegex = /app\.(post|get|put|patch)\s*\(|export\s+(default\s+)?async\s+function\s+(GET|POST|PUT|PATCH)|@app\.(post|get|put)\s*\(/i;
    const llmCallRegex = /(openai|anthropic|gemini|cohere|mistral)\.(chat|messages|generate|complete)|completions\.create|messages\.create|generateContent/i;
    const rateLimitRegex = /(rateLimit|rate_limit|rateLimiter|limiter|throttle|slowDown|express-rate-limit|upstash.*ratelimit|redis.*limit)/i;

    lines.forEach((line, index) => {
      const isRoute = routeRegex.test(line);
      if (!isRoute) return;

      // Check if there's an LLM call within ±20 lines of this route definition
      const routeCtx = lines.slice(index, Math.min(lines.length, index + 20)).join('\n');
      if (!llmCallRegex.test(routeCtx)) return;

      // Check for rate limiting in the broader context (±20 lines)
      const fullCtx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 20)).join('\n');
      if (!rateLimitRegex.test(fullCtx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
      }
    });
    return matches;
  },
};

// ─── 17. Recursive agent loop without max iteration guard ──────────────────────
// LLM04:2025 — An agent loop without a hard max_iterations cap can run indefinitely
// if the LLM never reaches a stop condition, consuming unbounded compute and budget.
const LLM_RECURSIVE_AGENT_LOOP: Rule = {
  id: 'LLM_RECURSIVE_AGENT_LOOP',
  owaspLLM: 'LLM04:2025',
  title: 'Agent loop missing max iteration guard — infinite loop / cost runaway risk',
  description: 'Agentic loops that lack an explicit maximum iteration or step limit can run indefinitely when the LLM fails to produce a terminal action. This leads to unbounded API costs, hung processes, and potential denial of service. Always enforce a hard cap on the number of agent steps.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const agentLoopRegex = /while\s*\(.*agent|for\s+\w+\s+in\s+.*agent|while\s+True|while\s*\(true\)/i;
    const iterGuardRegex = /(max_iter|maxIter|max_steps|maxSteps|max_turns|maxTurns|iteration.*limit|stop_condition|max_rounds|max_loops)\s*[=:<>]/i;
    const breakGuardRegex = /\bbreak\b|\bstop\b.*condition/i;

    lines.forEach((line, index) => {
      const isAgentLoop = agentLoopRegex.test(line) ||
        /\b(agent|executor|crew|pipeline)\.(run|invoke|execute|step)\b.*\bloop\b/i.test(line) ||
        // while True / while(true) loops that contain LLM calls nearby
        (/while\s*(True|true|\(true\))/i.test(line) &&
          /(agent|llm|openai|anthropic|chain|tool)/i.test(
            lines.slice(index, Math.min(lines.length, index + 15)).join('\n')
          ));

      if (!isAgentLoop) return;

      const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 15)).join('\n');
      if (!iterGuardRegex.test(ctx) && !breakGuardRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.73 });
      }
    });
    return matches;
  },
};

// ─── 18. Unsanitized user input passed to embedding API ───────────────────────
// LLM09:2025 — Vector/Embedding Poisoning: injecting adversarial text into embeddings
// can corrupt semantic search results and poison downstream RAG responses.
const LLM_EMBEDDING_INPUT_UNSANITIZED: Rule = {
  id: 'LLM_EMBEDDING_INPUT_UNSANITIZED',
  owaspLLM: 'LLM09:2025',
  title: 'Unsanitized user input fed directly to embedding API — embedding poisoning risk',
  description: 'Passing raw user-controlled text directly to an embedding API without sanitization enables embedding poisoning attacks, where adversarial inputs manipulate the vector space to corrupt semantic search results. Sanitize and validate user input before generating embeddings that will be stored in a vector database.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const embeddingCallRegex = /(embeddings\.create|embed_text|get_embedding|get_embeddings|vectorize|encode_text|create_embedding|openai\.embeddings|text_to_embedding)/i;
    const userInputRegex = /(req\.body|req\.query|request\.body|request\.json|request\.get_json|userInput|user_input|user_text|user_message|user_query)\b/i;
    const sanitizeRegex = /(sanitize|escape|strip|clean|validate|filter|trim\(\)|slice\(|substring|normalize)/i;

    lines.forEach((line, index) => {
      const isEmbeddingCall = embeddingCallRegex.test(line);
      if (!isEmbeddingCall) return;

      // Check if user input is referenced near this call
      const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 3)).join('\n');
      const hasUserInput = userInputRegex.test(ctx);
      if (!hasUserInput) return;

      const sanitizeCtx = lines.slice(Math.max(0, index - 8), index).join('\n');
      if (!sanitizeRegex.test(sanitizeCtx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
      }
    });
    return matches;
  },
};

// ─── 19. Vector store upsert without tenant/namespace isolation ──────────────
// LLM09:2025 — Without namespace/userId scoping, documents from one user can
// pollute the vector space of another, enabling cross-tenant data leakage.
const LLM_VECTOR_STORE_NO_NAMESPACE: Rule = {
  id: 'LLM_VECTOR_STORE_NO_NAMESPACE',
  owaspLLM: 'LLM09:2025',
  title: 'Vector store upsert missing namespace/tenant isolation — cross-user data leakage risk',
  description: 'Inserting embeddings into a shared vector store without namespace or userId scoping means all users share the same vector space. This can expose one user\'s documents to another user\'s semantic queries, creating a data privacy violation. Always scope vector store operations by tenant, user, or collection.',
  severity: 'MEDIUM',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const upsertRegex = /\.(upsert|add_documents|add_texts|from_documents|insert_many|addDocuments)\s*\(|vectorStore\.add\b|pinecone.*upsert|weaviate.*create_object|chroma.*add\b/i;
    const isolationRegex = /(namespace\s*[=:,]|collection\s*[=:,]|userId\s*[=:,]|tenantId\s*[=:,]|user_id\s*[=:,]|tenant_id\s*[=:,]|index_name\s*[=:,]|partition_key)/i;

    lines.forEach((line, index) => {
      if (!upsertRegex.test(line)) return;

      const ctx = lines.slice(Math.max(0, index - 10), Math.min(lines.length, index + 5)).join('\n');
      if (!isolationRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
      }
    });
    return matches;
  },
};

// ─── 20. LLM output fed into training/fine-tuning pipeline ────────────────────
// LLM03:2025 — Training Data Poisoning: using raw LLM outputs as training data
// without human review can amplify model biases and embed adversarial behaviors.
const LLM_EVAL_FEEDBACK_LOOP: Rule = {
  id: 'LLM_EVAL_FEEDBACK_LOOP',
  owaspLLM: 'LLM03:2025',
  title: 'LLM output used directly in training/fine-tuning pipeline without human review',
  description: 'Feeding LLM-generated outputs directly back into a training or fine-tuning dataset without human validation creates a poisoning feedback loop. Adversarially crafted prompts can inject malicious behaviors that become permanently encoded in subsequent model versions. Always require human review before LLM outputs enter training pipelines.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const llmOutputVars = new Set<string>();

    // Pre-pass: collect variables holding LLM output
    lines.forEach((line) => {
      const llmAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:client|openai|anthropic|llm|model|chain)\.(chat|messages|completions|generate|predict|run|invoke)/i
      );
      if (llmAssign) llmOutputVars.add(llmAssign[1]);

      // Content extraction vars
      const contentExtract = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*\w+\.(content|text|output|choices\[0\]\.message\.content)/i);
      if (contentExtract) {
        const sourceVar = line.match(/=\s*(\w+)\./)?.[1];
        if (sourceVar && llmOutputVars.has(sourceVar)) llmOutputVars.add(contentExtract[1]);
      }
    });

    const trainingRegex = /(fine.?tun|finetune|train.*model|update.*model|feedback.*dataset|append.*training|write.*jsonl|save.*dataset|push.*dataset|dataset.*push)/i;
    const reviewRegex = /(human_review|humanReview|approved|validated|manual_check|reviewed_by|requires_approval)/i;

    lines.forEach((line, index) => {
      if (!trainingRegex.test(line)) return;

      const ctx = lines.slice(Math.max(0, index - 10), Math.min(lines.length, index + 5)).join('\n');
      const hasLLMOutput = [...llmOutputVars].some(v => new RegExp(`\\b${v}\\b`).test(ctx)) ||
        /(completion|response|output|generated|llm_result)\b/i.test(ctx);

      if (hasLLMOutput && !reviewRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
      }
    });
    return matches;
  },
};

// ─── 21. Third-party model loaded without integrity verification ───────────────
// LLM05:2025 — Supply Chain: loading a model from a dynamic/user-controlled path
// without checksum or signature verification enables model tampering attacks.
const LLM_THIRD_PARTY_MODEL_NO_VERIFY: Rule = {
  id: 'LLM_THIRD_PARTY_MODEL_NO_VERIFY',
  owaspLLM: 'LLM05:2025',
  title: 'Third-party or dynamic model loaded without integrity verification — supply chain risk',
  description: 'Loading a model from a dynamic or externally controlled path without verifying its checksum or signature exposes the application to supply chain attacks. A compromised or tampered model file can execute arbitrary code or produce adversarially manipulated outputs. Always pin model versions and verify integrity hashes.',
  severity: 'MEDIUM',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const modelLoadRegex = /(from_pretrained|hub\.load|model\.load|torch\.load|tf\.saved_model\.load|load_model|AutoModel\.from_pretrained|AutoTokenizer\.from_pretrained)\s*\(/i;
    const dynamicPathRegex = /(req\.|request\.|user|input|config\.|os\.environ|process\.env|getenv|argv|sys\.argv|params\.|body\.)/i;
    const verifyRegex = /(sha256|checksum|hash_check|verify_hash|trust_remote_code\s*=\s*False|revision\s*=\s*["'][a-f0-9]{7,}["']|model_hash|integrity)/i;

    lines.forEach((line, index) => {
      if (!modelLoadRegex.test(line)) return;

      const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 3)).join('\n');
      if (!dynamicPathRegex.test(ctx)) return; // only flag dynamic/config-driven paths

      if (!verifyRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
      }
    });
    return matches;
  },
};

export const promptInjectionRules: Rule[] = [
  LLM_USER_INPUT_DIRECT,
  LLM_SYSTEM_PROMPT_INJECTION,
  LLM_TOOL_INPUT_INJECTION,
  LLM_NO_INPUT_GUARD,
  LLM_OUTPUT_EXEC,
  LLM_STRUCTURED_OUTPUT_UNVALIDATED,
  RAG_UNSANITIZED_RETRIEVAL,
  AGENT_TOOL_CALL_INJECTION,
  LLM_OUTPUT_AS_SYSTEM_PROMPT,
  LLM_JAILBREAK_PATTERN,
  LLM_HISTORY_INJECTION,
  LLM_PROMPT_LEAK,
  LLM_DATA_EXFILTRATION_TOOL,
  LLM_TOKEN_LIMIT_MISSING,
  LLM_NO_TIMEOUT,
  LLM_RATE_LIMIT_MISSING,
  LLM_RECURSIVE_AGENT_LOOP,
  LLM_EMBEDDING_INPUT_UNSANITIZED,
  LLM_VECTOR_STORE_NO_NAMESPACE,
  LLM_EVAL_FEEDBACK_LOOP,
  LLM_THIRD_PARTY_MODEL_NO_VERIFY,
];
