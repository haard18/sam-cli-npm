const fs = require('fs');

function parseReportToHTML(reportFile) {
    // Load the JSON data from the report file
    fs.readFile(reportFile, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading the report file:', err);
            return;
        }

        const issues = JSON.parse(data);

        // Organize issues by severity
        const issuesBySeverity = { low: [], medium: [], high: [] };
        issues.forEach(issue => {
            const severity = issue.severity;
            if (issuesBySeverity.hasOwnProperty(severity)) {
                issuesBySeverity[severity].push(issue);
            }
        });

        let htmlOutput = `
<html>
<head>
<title>Analysis Report</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="m-8">
<h1 class="text-3xl font-bold underline mb-4 text-center">Analysis Report</h1>
<!-- Flex container for side-by-side tables -->
<div class="flex flex-wrap justify-around -mx-2">
`;

        // Generate cards for each severity level
        Object.entries(issuesBySeverity).forEach(([severity, issues]) => {
            if (issues.length) { // Check if there are any issues of this severity
                const severityColors = {
                    low: "bg-blue-100 text-blue-800",
                    medium: "bg-yellow-100 text-yellow-800",
                    high: "bg-red-100 text-red-800"
                };
                const severityTitle = severity.charAt(0).toUpperCase() + severity.slice(1);

                htmlOutput += `
<div class="rounded overflow-hidden shadow-lg mb-4 px-2 w-full">
  <div class="px-6 py-4 ${severityColors[severity]}">
    <div class="font-bold text-xl mb-2">${severityTitle} Severity Issues</div>
    <table class="table-auto w-full">
      <thead>
        <tr class="bg-gray-200">
          <th class="px-4 py-2">Name</th>
          <th class="px-4 py-2">Description</th>
          <th class="px-4 py-2">Line</th>
        </tr>
      </thead>
      <tbody>`;
                issues.forEach(issue => {
                    htmlOutput += `
        <tr>
          <td class="border px-4 py-2">${issue.name}</td>
          <td class="border px-4 py-2">${issue.description}</td>
          <td class="border px-4 py-2">${issue.line}</td>
        </tr>`;
                });
                htmlOutput += `
      </tbody>
    </table>
  </div>
</div>`;
            }
        });

        // Close flex container and HTML document
        htmlOutput += "</div></body></html>";

        // Save the HTML output to a file
        fs.writeFile('report.html', htmlOutput, err => {
            if (err) {
                console.error('Error writing the HTML report:', err);
                return;
            }
            console.log("Report has been successfully rendered to HTML with Tailwind CSS.");
        });
    });
}

// Assuming the JSON report is saved as 'report.json'
parseReportToHTML('report.json');
module.exports = parseReportToHTML;
