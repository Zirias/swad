(async () => {
    let errmsg = document.querySelector('.error');
    let spinner = document.querySelector('.spinner');
    let form = document.getElementsByTagName('form')[0];
    let pwinput = form.querySelector('[name=pw]');
    let challenge = form.dataset.challenge;
    let difficulty = form.dataset.difficulty;

    if (!window.crypto || !window.crypto.subtle) {
	errmsg.innerHTML = 'Your browser does not support SubtleCrypto.';
	return;
    }

    if (!window.Worker) {
	errmsg.innerHTML = 'Your browser does not support Web Workers.';
	return;
    }

    errmsg.innerHTML = 'Calculating, please wait ...';
    spinner.style.display = 'block';

    function createWorker() {
	return function () {
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

	    addEventListener('message', async (event) => {
		let challenge = event.data.challenge;
		let difficulty = event.data.difficulty;
		let nonce = event.data.start;
		let step = event.data.step;

		let found = null;
		for (; found == null; nonce += step) {
		    found = b64num(nonce);
		    let hash = new Uint8Array(await sha256(challenge + found));
		    if (hash.length < difficulty) {
			found = null;
			continue;
		    }
		    for (let i = 0; i < difficulty; ++i) {
			let nibble = hash[Math.floor(i/2)]
			    >> (i%2===0?4:0) & 0xf;
			if (nibble !== 0) {
			    found = null;
			    break;
			}
		    }
		}
		postMessage(found);
	    });
	}.toString();
    }

    let workerUrl = URL.createObjectURL(new Blob([
	'(', createWorker(), ')()' ], {type: 'application/javascript'}));

    const workers = [];
    const nthreads = (navigator.hardwareConcurrency || 1);

    for (let t = 0; t < nthreads; ++t) {
	let worker = new Worker(workerUrl);
	worker.onmessage = (event) => {
	    workers.forEach((w) => w.terminate());
	    pwinput.setAttribute('value', event.data);
	    form.submit();
	}
	worker.onerror = (event) => {
	    workers.forEach((w) => w.terminate());
	    errmsg.innerHTML = 'An unexpected error occured, giving up.';
	    spinner.style.display = 'none';
	}
	workers.push(worker);
	worker.postMessage({
	    challenge,
	    difficulty,
	    start: t,
	    step: nthreads
	});
    }

    URL.revokeObjectURL(workerUrl);

})();
