Here's a basic README.md template for your Lua Analyzer package:

```markdown
# sam-cli-npm
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

A package to analyze Lua Contracts for vulnerabilities.

## Installation

Ensure you have Node.js (>=12.0.0) installed. You can install the package using npm:

```bash
npm install sam-cli-npm
```

## Usage

### Analyze Lua Files

To analyze a Lua file for vulnerabilities, run:

```bash
npm run analyze <file.lua>
```

Replace `<file.lua>` with the path to your Lua file.

### Generate HTML Report

To generate an HTML report from the JSON vulnerability report, run:

```bash
npm run report
```

This command generates a detailed HTML report (`report.html`) using Tailwind CSS.

## License

This project is licensed under the ISC License. See the [LICENSE](LICENSE) file for details.

## Bugs and Issues

Please report any bugs or issues [here](https://github.com/haard18/sam-cli-npm/issues).

## Repository

Find this project on GitHub: [https://github.com/haard18/sam-cli-npm](https://github.com/haard18/sam-cli-npm)

```

This template includes sections for installation instructions, usage examples, license information, bug reporting, and repository links. Feel free to customize it further based on additional details or features of your package.