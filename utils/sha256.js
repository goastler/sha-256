import crypto from 'crypto'

function printBytesAsArray(byteArray) {
    // Convert the array to the desired format
    const formattedString = `[${byteArray.join(', ')}],`;

    // Print the formatted string
    console.log(formattedString);
}

const main = async () => {
	for(let i = 1; i <= 1024; i++) {
		const sha256 = crypto.createHash('sha256')
		const data = 'a'.repeat(i)
		sha256.update(data)
		const hash = sha256.digest()
		printBytesAsArray(hash)
	}
}

main().catch(console.error)
