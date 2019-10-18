function send_data(data, callback, key){
	var xhr = null; 
	if(window.XMLHttpRequest){ // Firefox et autres
		xhr = new XMLHttpRequest(); 
	}else if(window.ActiveXObject){ // Internet Explorer 
		try {
			xhr = new ActiveXObject('Msxml2.XMLHTTP');
		} catch (e) {
			xhr = new ActiveXObject('Microsoft.XMLHTTP');
		}
	}else{
		alert('Votre navigateur ne supporte pas les objets XMLHTTPRequest...'); 
		xhr = false; 
	}
	xhr.onreadystatechange = function(){
		if( xhr.readyState < 4 ){
			//loading
		}else if(xhr.readyState == 4 && xhr.status == 200){
			//end loading
			callback(xhr.responseText, key);
		}else if(xhr.readyState == 4 && xhr.status != 200){
			//end loading
			callback(xhr.responseText, key, true);
		}
	}
	xhr.open('POST', '/', true);
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	xhr.send(data);
}

function buf2hex(buffer){
	return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2buf(string) {
	return new Uint8Array(string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function str2buf(string){
	var bytes = new Uint8Array(string.length);
	for (var i = 0; i < string.length; i++){
		bytes[i] = string.charCodeAt(i);
	}
	return bytes;
}

function buf2str(buffer){
	var str = "";
	for (var i = 0; i < buffer.byteLength; i++){
		str += String.fromCharCode(buffer[i]);
	}
	return str;
}

function sha256(message){
	var encoder = new TextEncoder()
	return window.crypto.subtle.digest(
		{
			name: "SHA-256",
		},
		new Uint8Array(encoder.encode(message))
	).then(function(hash){
		return buf2hex(hash);
	}).catch(function(err){
		console.error(err);
	});
}

function aes256_import_key(hex_key){
	return window.crypto.subtle.importKey(
		"raw",
		hex2buf(hex_key).buffer,
		{
			name: "AES-CBC",
			length: 256,
		},
		false,
		["encrypt", "decrypt"]
	).then(function(key){
		return key;
	})
}

function aes256_encrypt(key, string_data){
	var iv = window.crypto.getRandomValues(new Uint8Array(16));
	return window.crypto.subtle.encrypt(
		{
			name: "AES-CBC",
			iv: iv,
		},
		key,
		str2buf(string_data)
	)
	.then(function(encrypted){
		return Promise.resolve({
			"cipher": buf2hex(encrypted),
			"iv": buf2hex(iv)
		})
	})
	.catch(function(err){
		console.error(err);
	});
}

function aes256_decrypt(key, hex_iv, hex_data){
	return window.crypto.subtle.decrypt(
		{
			name: "AES-CBC",
			iv: hex2buf(hex_iv),
		},
		key,
		hex2buf(hex_data)
	)
	.then(function(decrypted){
		return buf2str(new Uint8Array(decrypted));
	})
	.catch(function(err){
		console.error(err);
	});
}

async function submit_link(){
	var link = document.getElementById('url_input').value;
	var key = buf2hex(window.crypto.getRandomValues(new Uint8Array(4)));
	var link_id = await sha256(key)
							.then(hash => sha256(hash))
							.then(hash => sha256(hash))
							.then(hash => sha256(hash));
	
	var aes_key = await sha256(key);
	
	var encrypted_link = await aes256_import_key(aes_key).then(key => aes256_encrypt(key, link));

	var data = 'link_id='+link_id+"&encrypted_link="+JSON.stringify(encrypted_link);
	send_data(data, show_link, key);
}

function show_link(response, key, error=false){
	if(!error){
		var result = JSON.parse(response);
		if(result["state"] == "OK"){
			document.getElementById("result").innerHTML = "Your protected link : " + url + '/#' + key;
			return;
		}
	}
	document.getElementById("result").innerHTML = '<span class="error">' + response + '</span>';
}

async function get_link(){
	grecaptcha.ready(function() {
		grecaptcha.execute(recaptcha_public_key, {action: 'get_link'}).then(async function(token) {
			var key = window.location.hash.split('?')[0].split('&')[0].replace('#', '')
			var link_id = await sha256(key)
							.then(hash => sha256(hash))
							.then(hash => sha256(hash))
							.then(hash => sha256(hash));
			var aes_key = await sha256(key);
			var data = 'token='+token+'&link_id='+link_id;
			send_data(data, continue_link, key);
		});
	});
}

async function continue_link(response, key, error=false){
	try {
		if(error){
			throw 'HTTP error';
		}
		var result = JSON.parse(response);
		console.log(result["state"])
		if(result["state"] != "OK"){
			throw 'State error';
		}else{
			var encrypted_link = JSON.parse(result["encrypted_link"]);
			var aes_key = await sha256(key);
			var decrypted_link = await aes256_import_key(aes_key).then(key => aes256_decrypt(key, encrypted_link.iv, encrypted_link.cipher));
			document.location = decrypted_link;
		}
	} catch(error) {
		document.getElementById("result").innerHTML = '<span class="error">' + response + '</span>';
	}
}

document.addEventListener("DOMContentLoaded", function() {
	if(window.location.hash.length > 0){
		document.getElementById('check').style.display = 'block';
	}else{
		document.getElementById('home').style.display = 'block';
	}
});