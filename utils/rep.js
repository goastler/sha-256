const char = process.argv[2];
const n = parseInt(process.argv[3], 10);

if (!char || isNaN(n)) {
    console.error("Usage: node script.js <char> <N>");
    process.exit(1);
}

console.log(char.repeat(n));
