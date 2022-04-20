// class User{
//     constructor(){
//
//     }
// }

var keyPair;
var HMACKey;

/* -----------------------------------------------------------------------------
                                Register
 -----------------------------------------------------------------------------*/

 function registerPost(event) {

    event.preventDefault();

    let formUser = document.getElementById("r_username").value;
    let formPassword = document.getElementById("r_password").value;
    let formReentered = document.getElementById("r_reentered").value;

    var registerForm = {
         username: formUser,
         password: formPassword,
         reentered: formReentered,
    };
    console.log(JSON.stringify(registerForm));

    fetch('/register', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(registerForm),
    })
    .then(response => response.json())
    .then(retData => {
        if (retData["error"] != "success"){
            console.log(retData["error"]);
            registerError(retData["error"]);
        }
        else {
            generateKeyPair(formUser);
            document.getElementById("registerInfo").style.color = "green";
            document.getElementById("registerInfo").textContent = "Successfully created your account";
            document.getElementById("registerFormId").reset();
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
 }

function registerError(errorMessage) {
    document.getElementById("registerInfo").style.color = "red";
    if (errorMessage == 'password_not_matching'){
        document.getElementById("registerInfo").textContent = "The passwords do not match.";
    }
    else if (errorMessage == 'password_too_short'){
        document.getElementById("registerInfo").textContent = "The password is too short. Minimum 8 characters is required.";
    }
    else if (errorMessage == 'user_taken'){
        document.getElementById("registerInfo").textContent = "The username has already been taken.";
    }

}

function generateKeyPair(user) {
    console.log("Generating key pair");

    keyPair = crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            hash: {name: "SHA-256"},
            publicExponent: new Uint8Array([1, 0, 1]),
        },
        true,
        ['encrypt', 'decrypt']
    ).then(function (keyPair) {
        exportKeys(keyPair, user);
    } )
}

function exportKeys(keyPair, user) {
    window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
    ).then(function (privateKey) {
        let byteCode = String.fromCharCode.apply(null, new Uint8Array(privateKey))

        localStorage.setItem(user, window.btoa(byteCode));

        // console.log("LOCAL STORAGE VAR: " + localStorage.getItem(user));

    }).catch(function (err) {
        console.log(err);
    });

    window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
    ).then(function (publicKey) {
        let byteCode = String.fromCharCode.apply(null, new Uint8Array(publicKey))

        postNewUser(user, window.btoa(byteCode));

    }).catch(function (err) {
        console.error(err);
    });
}

function postNewUser(user, publicK) {

    var newUser = {
         username: user,
         publicKey: publicK
    };

    fetch('/add_user', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(newUser),
    })
    .then(response => response.json())
    .then(retData => { retData
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}

/* -----------------------------------------------------------------------------
                                Login
 -----------------------------------------------------------------------------*/
// Makes sure that user is logged in
checkLogin();
function checkLogin() {
    if (window.location.href.match('msg_window')){
        if (getCookie("currentUser") == null){
            window.location.href = "/login";
        }
        else{
            viewNewMessage();
        }
    }
}

/* -----------------------------------------------------------------------------
                                Message Window
 -----------------------------------------------------------------------------*/
// Views message
function viewSelectedMessage () {
    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "none";

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "block";
    // if (messageContainer.style.display == "block"){
    //     messageContainer.style.display = "none";
    // }
    // else {
    //     messageContainer.style.display = "block";
    // }


}

function viewNewMessage() {
    // console.log("Selected to create new message");
    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "block";
    // if (inputContainer.style.display == "block"){
    //     inputContainer.style.display = "none";
    // }
    // else {
    //     inputContainer.style.display = "block";
    // }

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "none";

    var senderField = document.getElementById("senderField");
    senderField.textContent = "From: " + getCookie("currentUser");
}

async function sendMessage(event) {
    event.preventDefault();

    // Form variables
    var messageForm = document.getElementById("sendMessageForm");
    var senderFieldLabel = document.getElementById("senderField").textContent;
    var senderField = senderFieldLabel.replace('From: ', '');
    var recipientField = document.getElementById("recipientField").value;
    var msgField = document.getElementById("msgTextField").value;

    // Generates session key if needed
    await sessionKeyHelper(senderField, recipientField);

    // Retrieves session key
    let DBsessionKey = await getSessionKey(senderField, recipientField);
    if (DBsessionKey == null){
        console.error("Session key could not be retrieved");
    }

    // console.log(Date.now());
    // console.log(new Date(Date.now()));
    // console.log(new Date(Date.now()).toLocaleString());

    // Creates msg + time stamp string
    var msgstamp = msgField + Date.now();
    console.log(msgstamp);

    // Session key as object
    let sessionKeyObj = await importSessionKeyObject(DBsessionKey);
    console.log(typeof sessionKeyObj);

    //
    let encryptedMessage = await encryptStringAES(sessionKeyObj, msgstamp);
    console.log(typeof encryptedMessage);

    if (HMACKey == null){
        HMACKey = await generateHMACKey();
    }

    let MACsignature = await window.crypto.subtle.sign(
      "HMAC",
      HMACKey,
      encryptedMessage
    );


    postNewMessage(senderField, recipientField, encryptedMessage, MACsignature);


    // generateMACString(sessionKeyObj, encryptedMessage);

}

function postNewMessage(senderField, recipientField, enc_Message, sig) {

    var newMessage = {
         sender : senderField,
         recipient : recipientField,
         enc_msg : enc_Message,
         hmacSig : sig
    };

    fetch('/post_newMessage', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(newMessage),
    })
    // .then(response => response.json())
    // .then(retData => { retData
    // })
    .catch((error) => {
        console.error('Error: ', error);
    });
}



async function sessionKeyHelper(senderField, recipientField) {
    let DBsessionKey = await getSessionKey(senderField, recipientField);

    // Use decrypt encrypted session key to then encrypt a message
    if (DBsessionKey != null) {
        // console.log(DBsessionKey);
        document.getElementById("recipientError").textContent = "";

    }

    // Create session key (if user exists)
    else{
        console.log("No session key or user does not exist");

        // Check if user exists first
        const recipient_publicKey = await getPublicKey(recipientField);


        if (recipient_publicKey == null){
            // Not exist:
            console.log("User not found");
            document.getElementById("recipientError").textContent = "Username not found";
        }
        else if (recipient_publicKey != null){
            // User exists: Generate session key
            console.log("Generating session key");

            // Generate session key for A and B
            let newSessionKey = await generateSessionKey();
            const sessionKeyRaw = exportCryptoKey(newSessionKey);
            // console.log(typeof sessionKeyRaw);
            // console.log(sessionKeyRaw);

            // Sender public key
            const sender_publicKey = await getPublicKey(senderField);

            // Sender encrypted string of pk and sk
            const sender_Enc_String = await generateEnc_PKSK(sender_publicKey, sessionKeyRaw);
            // console.log(sender_Enc_String);

            // Recipient encrypted string of pk and sk
            const recipient_Enc_String = await generateEnc_PKSK(recipient_publicKey, sessionKeyRaw);
            // console.log(recipient_Enc_String);

            if (sender_Enc_String != null && recipient_Enc_String != null) {
                postNewSessionKey(senderField, sender_Enc_String, recipientField, recipient_Enc_String);
            }
        }
    }
}

function postNewSessionKey(senderField, sender_Enc_String, recipientField, recipient_Enc_String) {
    var sessionKeys = {
         [senderField]: sender_Enc_String,
         [recipientField]: recipient_Enc_String
    };

    fetch('/add_sessionkeysEntry', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(sessionKeys),
    })
    // .then(response => response.json())
    // // .then(retData => { retData
    // // })
    .catch((error) => {
        console.error('Error: ', error);
    });
}

async function generateHMACKey() {
    return await window.crypto.subtle.generateKey(
        {
            name: "HMAC",
            hash: {name: "SHA-512"}
        },
        true,
        ["sign", "verify"]
    );
}

function generateMACString(sessionKey, encoded){
    return window.crypto.subtle.sign(
        "HMAC",
        sessionKey,
        encoded
    );
}

async function generateEnc_PKSK(publicKeyString, sessionKeyRaw) {

    const publicKeyObj = await importRSAKey(publicKeyString);
    // console.log(typeof publicKeyObj);

    const enc_String = await encryptString(publicKeyObj, sessionKeyRaw);
    // console.log(enc_String);
    if (enc_String == null){
        console.log("Encryption failed");
        return null;
    }
    else{
        return convertArrayBufferToBase64(enc_String);
        // console.log(base64Enc);
    }
}

async function importRSAKey(pem) {
    // fetch the part of the PEM string between header and footer
    // const pemHeader = "-----BEGIN PUBLIC KEY-----";
    // const pemFooter = "-----END PUBLIC KEY-----";
    //
    // const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pem);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return await window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
        name: "RSA-OAEP",
        hash: "SHA-256"
    },
    true,
    ["encrypt"]
    );
}

async function exportCryptoKey(key) {
  const exported = await window.crypto.subtle.exportKey(
    "raw",
    key
  );
  const exportedKeyBuffer = new Uint8Array(exported);

  const keyString = `[${exportedKeyBuffer}]`;
  return keyString;
}

function importSessionKeyObject(rawKey){
    // const binaryDerString = window.atob(pem);
    // // convert from a binary string to an ArrayBuffer
    // const binaryDer = str2ab(binaryDerString);
    // console.log("rawKey: "+ rawKey);
    // const utf8Key = encodeString(rawKey);
    const utf8Key = window.crypto.getRandomValues(new Uint8Array(16));
    console.log(typeof utf8Key);

    return window.crypto.subtle.importKey(
    "raw",
    utf8Key,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
    );
}

function generateSessionKey(){
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

function encryptStringAES(key, string){
    var encoded = encodeString(string);
    let iv = window.crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        encoded
    );
}

function encryptString(key, string){
    var encoded = encodeString(string);

    return crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP'
        },
        key,
        encoded
    );
}

function decryptString(encrypted, key){
    var decrypt = crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP'
        },
        key,
        encrypted
    );
}

function encodeString(string) {
    var encoder = new TextEncoder();
    return encoder.encode(string);
}

function decodeString(encoded) {
    var decoder = new TextDecoder();
    return encoder.encode(string);
}

// Set for Message Window
if (getCookie("currentUser") != null && document.getElementById("fromLabel") != null) {
    // console.log("fromLabel: exists");
    document.getElementById("fromLabel").textContent = "From: " + getCookie("currentUser");
}

/* -----------------------------------------------------------------------------
                                Database Calls.
 -----------------------------------------------------------------------------*/

function getPublicKey(user) {

    var getUser = {
         username: user,
    };

    return fetch('/get_public_key', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(getUser),
    })
    .then(response => response.json())
    .then(retData => {
        // return retData;
        if ("error" in retData){
            // console.log(retData["error"]);
            return null;
        }
        else {
            // console.log(retData["public_key"]);
            return retData["public_key"];
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}

function getSessionKey(sender, recipient) {

    var getMessagePoints = {
         sender: sender,
         recipient: recipient
    };

    // console.log("sender: " + sender);
    // console.log("recipient: " + recipient);

    return fetch('/get_session_key', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(getMessagePoints),
    })
    .then(response => response.json())
    .then(retData => {
        if ("error" in retData){
            // console.log(retData["error"]);
            return null;
        }
        else {
            // console.log(retData["session_key"]);
            return retData["session_key"];
            // return retData;
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });


}

/* -----------------------------------------------------------------------------
                                Misc.
 -----------------------------------------------------------------------------*/

function myFunction(){
    var inputVal = document.getElementById("msgTextField").value;
    console.log("Cookies: " + document.cookie);
    alert(inputVal);
    window.location.href = "/msg_window"
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function convertArrayBufferToBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

/* -----------------------------------------------------------------------------
                                Cookies
 -----------------------------------------------------------------------------*/

function getCookie(name){
    var nameEdit = name + "=";

    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++){
        var cookie = cookies[i];
        while (cookie.charAt(0) == ' ') {
            cookie = cookie.substring(1, cookie.length);
        }
        if (cookie.indexOf(nameEdit) == 0) {
            return cookie.substring(nameEdit.length, cookie.length);
        }
    }
    return null;
}

function deleteCookie(name){
    var cookies = document.cookie.split(";");

    for (var i = 0; i < cookies.length; i++){
        var cookie = cookies[i];
        while (cookie.charAt(0) == ' ') {
            cookie = cookie.substring(1, cookie.length);
        }
        if (cookie.indexOf(nameEdit) == 0) {
            document.cookie = cookies[i] + "=;expires=" + new Date(0).toUTCString();
        }
    }
    return null;
}

function clearCookies(){

    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++){
        document.cookie = cookies[i] + "=;expires=" + new Date(0).toUTCString();
    }
}
