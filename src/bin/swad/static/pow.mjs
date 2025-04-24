(async () => {
    let form = document.getElementsByTagName('form')[0];
    let pwinput = form.querySelector('[name=pw]');
    let challenge = form.dataset.challenge;
    let difficulty = form.dataset.difficulty;

    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    function b64num(num) {
	let b64 = '';
	do {
	    b64 += alphabet[num%64];
	    num = Math.floor(num/64);
	} while (num !== 0);
	return b64;
    }

    function sha256(str) {
	const encoded = new TextEncoder().encode(str);
	return crypto.subtle.digest("SHA-256", encoded.buffer);
    }

    let nonce = 0;
    let found = null;
    for (; found == null; ++nonce) {
	found = b64num(nonce);
	let hash = new Uint8Array(await sha256(challenge + found));
	if (hash.length < difficulty) {
	    found = null;
	    continue;
	}
	for (let i = 0; i < difficulty; ++i) {
	    let nibble = hash[Math.floor(i/2)] >> (i%2===0?4:0) & 0xf;
	    if (nibble !== 0) {
		found = null;
		break;
	    }
	}
    }

    pwinput.setAttribute('value', found);
    form.submit();
})();
