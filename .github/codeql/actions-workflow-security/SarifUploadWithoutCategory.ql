/**
 * @name SARIF upload without an explicit category
 * @description Detects upload-sarif steps that do not set a stable category for code-scanning analysis identity.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision high
 * @id actions/sarif-upload-without-category
 * @tags actions
 *       security
 */

import actions

from UsesStep step
where
  step.getCallee().regexpMatch("(?i)^github/codeql-action/upload-sarif@") and
  not exists(Expression category |
    category = step.getArgumentExpr("category") and
    category.getExpression().regexpMatch("(?s).+")
  )
select step,
  "The SARIF upload step does not set a stable category. Add a category such as 'devskim/static-analysis' or 'trivy/filesystem' so GitHub code scanning keeps multi-tool results distinct."
