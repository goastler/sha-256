function hexToByteArray(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error("Hex string must have an even length.");
    }
    const byteArray = [];
    for (let i = 0; i < hex.length; i += 2) {
        byteArray.push(parseInt(hex.substr(i, 2), 16));
    }
    return byteArray;
}

const hexString = process.argv[2];
try {
    const byteArray = hexToByteArray(hexString);
    console.log(byteArray);
} catch (error) {
    console.error(error.message);
}
