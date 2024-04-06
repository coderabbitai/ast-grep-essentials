# ast-grep-essentials

## Overview

ast-grep-essentials, a package designed to enhance the security of your codebase through ast-grep rules. This package
provides essential security rules, utilities, and tests to help you identify and mitigate potential vulnerabilities in
your code.

> Please read the coderabbit [documentation](https://docs.coderabbit.ai/guides/review-instructions) to understand how to
> use ast-grep in coderabbit reviews.

## Structure

```plaintext
ast-grep-essentials
│
├── rules
│   ├── javascript
│   │   ├── jwt
│   │   │   ├── rule1.yml
│   │   │   ├── rule2.yml
│   │   │   └── ...
│   │   ├── ...
│   │   └── ...
│   └── go
│       ├── jwt-go
│       │   ├── rule1.yml
│
├── utils
│   ├── script1.yml
│   ├── script2.yml
│   └── ...
│
└── tests
    ├── javascript
    │   ├── rule1-test.yml
    │   ├── rule2-test.yml
    │   └── ...
    ├── ...
    └── ...
```

The package is organized into three main directories:

- **rules:** Contains ast-grep rules categorized by language and security category.
- **utils:** Houses utility configs to support rule management.
- **tests:** Includes test cases for validating the effectiveness of the rules across different languages.

### Rules Structure

Within the rules directory, you'll find the following structure:

- **language:** Each language supported by ast-grep (e.g., Python, JavaScript).
- **category:** Rules categorized based on security concerns (e.g., Input Validation, Authentication).

#### Rule file

Each rule file should have the following structure:

```yaml
# unique across the package, not just the language
id: rule-id
# the language property that the rule is going to get matched against
language: "language" # e.g., javascript, go
# the message property is going to get used on the review process and it's important to be clear on what the rule match means.
message: "Rule message"
# the note property is going to get used on the review process and it's important to contain as much side meaningful information as possible.
note: "Rule note"
# severity level of the rule (e.g., hint, warning) "error" is also valid but is not going to get approved.
severity: "severity"
# ast-grep rule property, check coderabbiit documentation for more information
rule:
  ...
```

### Tests Structure

Inside the tests directory, tests are organized by language:

- **language:** Test cases specific to the corresponding language's rules.
- **rule-file:** each test rule file should have by convention the rule-file-name-test.yml

> Writing tests should follow the ast-grep testing rules format. Please refer to the
> ast-grep [documentation](https://ast-grep.github.io/guide/test-rule.html#test-case-configuration)