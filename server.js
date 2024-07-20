const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

function analyzeCode(filePath) {
    return new Promise((resolve, reject) => {
        // Pass the file path as an argument to the Python script
        const pythonProcess = spawn('python', [path.join(__dirname, 'test.py'), filePath]);

        let output = '';
        pythonProcess.stdout.on('data', (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
            console.error(`Python stderr: ${data}`);
        });

        pythonProcess.on('close', (code) => {
            if (code === 0) {
                console.log('Report generated and saved'); // Add console.log statement here
                resolve(output);
            } else {
                reject(new Error(`Python script exited with code ${code}`));
            }
        });
    });
}

if (require.main === module) {
    const filePath = process.argv[2];
    if (!filePath) {
        console.error('Please provide a file path as an argument');
        process.exit(1);
    }

    analyzeCode(filePath).then((output) => {
        console.log(output);
    }).catch((err) => {
        console.error(err);
    });
}
