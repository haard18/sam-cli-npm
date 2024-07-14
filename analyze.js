const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");
const analyzeLuaFiles = require("./index.js");
const parseReportToHTML = require("./test.js");  // Adjust if the function is in another file

function generateHTMLReport(data) {
    const reportData = JSON.parse(data);
    let htmlContent = `<html><head><title>Analysis Report</title></head><body><h1>Analysis Report</h1>`;

    reportData.forEach(item => {
        htmlContent += `<div><h2>${item.name}</h2><p>${item.description}</p></div>`;
    });

    htmlContent += `</body></html>`;
    return htmlContent;
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const filePath = args[0];

    if (!filePath) {
        console.error("Usage: npm run run-analysis <file.lua>");
        process.exit(1);
    }

    console.log(`Starting analysis for file: ${filePath}`);

    analyzeLuaFiles(filePath)
        .then(() => {
            console.log('Analyzing Lua files completed. Generating HTML report from report.json');
            parseReportToHTML('report.json');
        })
        .catch((error) => {
            console.error("Error:", error);
        });
}

module.exports = { analyzeLuaFiles, generateHTMLReport };
