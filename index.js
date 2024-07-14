const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");

function generateHTMLReport(data) {
    const reportData = JSON.parse(data);
    let htmlContent = `<html><head><title>Analysis Report</title></head><body><h1>Analysis Report</h1>`;

    reportData.forEach(item => {
        htmlContent += `<div><h2>${item.name}</h2><p>${item.description}</p></div>`;
    });

    htmlContent += `</body></html>`;
    return htmlContent;
}

function analyzeLuaFiles(filePath) {
    return new Promise((resolve, reject) => {
        const fullPath = path.resolve(filePath).replace(/\\/g, "\\\\"); // Ensure backslashes are escaped

        console.log(`Checking if the file exists at path: ${fullPath}`);

        if (!fs.existsSync(fullPath)) {
            console.error(`File not found at path: ${fullPath}`);
            return reject(`File not found: ${fullPath}`);
        }

        console.log(`File found. Executing analyze.py on: ${fullPath}`);

        // Use double quotes around the path to handle spaces and special characters
        exec(`python3 analyze.py "${fullPath}"`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Execution error for analyze.py on: ${fullPath}`);
                return reject(`Error executing analyze.py: ${error.message}`);
            }
            if (stderr) {
                console.error(`stderr from analyze.py on: ${fullPath}`);
                return reject(`stderr: ${stderr}`);
            }
            console.log(`Analysis completed successfully for: ${fullPath}`);
            resolve(stdout);
        });
    });
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const filePath = args[0];
    const generateReportFlag = args.includes('--generate-report');

    if (!filePath) {
        console.error("Usage: npm run analyze <file.lua> [--generate-report]");
        process.exit(1);
    }

    if (generateReportFlag) {
        console.log('Generating HTML report from report.json');

        const jsonFilePath = path.join(__dirname, 'report.json'); // Adjust 'report.json' to your JSON file's path

        fs.readFile(jsonFilePath, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading JSON file:', err);
                return;
            }

            const htmlContent = generateHTMLReport(data);

            const htmlFilePath = path.join(__dirname, 'report.html');
            fs.writeFile(htmlFilePath, htmlContent, err => {
                if (err) {
                    console.error('Error writing HTML report:', err);
                    return;
                }
                console.log('Report generated successfully:', htmlFilePath);
            });
        });
    } else {
        console.log(`Starting analysis for file: ${filePath}`);

        analyzeLuaFiles(filePath)
            .then((result) => {
                console.log("Vulnerability Analysis Result:");
                console.log(result);
            })
            .catch((error) => {
                console.error("Error:", error);
            });
    }
}

module.exports = analyzeLuaFiles;
