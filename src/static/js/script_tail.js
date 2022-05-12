// class User{
//     constructor(){
//
//     }
// }


var keyPair;

/* -----------------------------------------------------------------------------
                                Register
 -----------------------------------------------------------------------------*/

 function generateSalt64() {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var salt = "";
    for (var i = 0; i < 64; i++) {
      salt += chars.charAt(Math.floor(Math.random() * chars.length));
   }
   return salt;
}

 async function hash_pwd(pwd, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pwd + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHexStr = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
  return hashHexStr;
}

async function registerPost(event) {

   event.preventDefault();

   let formUser = document.getElementById("r_username").value;
   let formPassword = document.getElementById("r_password").value;
   let formReentered = document.getElementById("r_reentered").value;

   if (formPassword != formReentered) {
       registerError("registerInfo");
   } else {

       var slt = generateSalt64();
       var salted_hash = await hash_pwd(formPassword, slt);
      
      
       var registerForm = {
            username: formUser,
            hashed: salted_hash,
            salt: slt,
       };
       

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
               registerError(retData["error"]);
           }
           else {
               generateKeyPair(formUser);
               document.getElementById("registerInfo").style.top = 0;
               document.getElementById("registerInfo").style.left = 0;
               //document.getElementById("registerInfo").style.width = '100%';
               //document.getElementById("registrInfo").style.fontSize = 42;
               document.getElementById("registerInfo").style.color = "green";
               //document.getElementById("registerInfo").style.position = 'absolute'
               document.getElementById("registerInfo").textContent = "Successfully created your account";
               document.getElementById("registerFormId").reset();
           }
       })
       .catch((error) => {
           console.error('Error: ', error);
       });
    }
}

function registerError(errorMessage) {
    document.getElementById("registerInfo").style.color = "red";
    if (errorMessage == 'password not matching'){
        document.getElementById("registerInfo").textContent = "The passwords do not match.";
    }
    else if (errorMessage == 'password too short'){
        document.getElementById("registerInfo").textContent = "The password is too short. Minimum 8 characters is required.";
    }
    else if (errorMessage == 'user taken'){
        document.getElementById("registerInfo").textContent = "The username has already been taken.";
    }

}

function generateKeyPair(user) {
    // console.log("Generating key pair");

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
function checkLogin() {
    if (window.location.href.match('msg_window')){
        // if (getCookie("currentUser") == null){
        //     window.location.href = "/login";
        // }
        if (sessionStorage.getItem("currentUser") == null){
            window.location.href = "/login";
        }
        else{
            viewNewMessage();
        }
    }
}

function loginPost(user, publicK) {

    event.preventDefault();
    
    let formUser = document.getElementById("l_username").value;
    let formPassword = document.getElementById("l_password").value;

    var loginForm = {
         username: formUser,
         password: formPassword
    };

    fetch('/login', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(loginForm),
    })
    .then(response => response.json())
    .then(retData => {
        // console.log(retData);
        if ("failed" in retData){
            document.getElementById("loginInfo").textContent = "Invalid username or password";
        }
        else if ("success" in retData){
            sessionStorage.setItem("currentUser", formUser);
            window.location.href = "/msg_window";
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}


/* -----------------------------------------------------------------------------
                                Message Window
 -----------------------------------------------------------------------------*/
// Views container to send messages
function viewNewMessage() {
    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "block";

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "none";

    var senderField = document.getElementById("senderField");
    // senderField.textContent = "From: " + getCookie("currentUser");
    senderField.textContent = "From: " + sessionStorage.getItem("currentUser");
}

var lastMessageTime;
const ONE_SECOND = 1000;
var delay = 0.5;

async function sendMessage(event) {
    event.preventDefault();

    if (Date.now() - (delay * ONE_SECOND) < lastMessageTime) {
        // console.log("Under " + delay + " seconds");
        return;
    }

    // Form variables
    var messageForm = document.getElementById("sendMessageForm");
    var senderFieldLabel = document.getElementById("senderField").textContent;
    var senderField = senderFieldLabel.replace('From: ', '');
    var recipientField = document.getElementById("recipientField").value;
    var msgField = document.getElementById("msgTextField").value;

    // Generates session key if needed
    await sessionKeyHelper(senderField, recipientField);

    // Retrieves session key
    let DBsessionKeyDict = await getSessionKey(senderField, recipientField);

    if (DBsessionKeyDict == null){
        // console.log("Session key could not be retrieved");
        return;
    }

    // Creates msg + time stamp string
    var msgstamp = msgField + Date.now();

    // Session key as object
    var PKSKString;
    if (DBsessionKeyDict["sender"] === senderField){
        PKSKString = DBsessionKeyDict["sender_enc"]
    }
    else if (DBsessionKeyDict["recipient"] === senderField){
        PKSKString = DBsessionKeyDict["recipient_enc"]
    }

    var sessionKeyAB = await generateDec_PKSK(localStorage.getItem(senderField), convertBase64ToArrayBuffer(PKSKString));
    // console.log("sessionKeyAB type: " + sessionKeyAB);

    let sessionKeyObj = await importSessionKeyObject(sessionKeyAB);

    iv = convertBase64ToArrayBuffer(DBsessionKeyDict["iv"]);
    //
    let encryptedMessage = await encryptStringAES(sessionKeyObj, msgstamp, iv);
    // console.log(typeof encryptedMessage);
    //
    // console.log(DBsessionKeyDict["hmac"]);
    let HMACKey = await generateHMACKeyObject(encodeString(DBsessionKeyDict["hmac"]));

    if (HMACKey == null) {
        console.log("hmac failed");
        return;
    }
    //
    //
    let MACsignature = await window.crypto.subtle.sign(
        "HMAC",
        HMACKey,
        encryptedMessage
    );
    document.getElementById("recipientError").textContent= "";
    postNewMessage(senderField, recipientField, convertArrayBufferToBase64(encryptedMessage), convertArrayBufferToBase64(MACsignature));
    lastMessageTime = Date.now();
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
    .then(retData => {
        if ("status" in retData){
            document.getElementById("sendMessageForm").reset();
        }
    })
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
        // console.log("Not null");
    }

    // Create session key (if user exists)
    else{
        // console.log("No session key or user does not exist");

        // Check if user exists first
        const recipient_publicKey = await getPublicKey(recipientField);


        if (recipient_publicKey == null){
            // Not exist:
            // console.log("User not found");
            document.getElementById("recipientError").textContent = "Username not found";
        }
        else if (recipient_publicKey != null){
            // User exists: Generate session key
            // console.log("Generating session key");

            // Generate session key for A and B
            let newSessionKey = await generateSessionKey();
            // console.log("Session key: " + typeof newSessionKey);
            const sessionKeyRaw = exportCryptoKey(newSessionKey);
            // console.log("sessionKeyRaw: " + typeof sessionKeyRaw);

            // Sender public key
            const sender_publicKey = await getPublicKey(senderField);

            // Sender encrypted string of pk and sk
            const sender_Enc_String = await generateEnc_PKSK(sender_publicKey, sessionKeyRaw);

            // Recipient encrypted string of pk and sk
            const recipient_Enc_String = await generateEnc_PKSK(recipient_publicKey, sessionKeyRaw);

            // Create new HMAC
            let HMACKey = await generateHMACKey();

            // Create new iv
            let iv = window.crypto.getRandomValues(new Uint8Array(12));

            if (sender_Enc_String != null && recipient_Enc_String != null) {
                let hmacString = await generateHMACString(HMACKey);
                postNewSessionKey(senderField, sender_Enc_String, recipientField, recipient_Enc_String, convertArrayBufferToBase64(hmacString), convertArrayBufferToBase64(iv));
            }

        }
    }
}

function generateHMACString(HMACKey) {
    return crypto.subtle.exportKey("raw", HMACKey);
}

function generateHMACKeyObject(hmacKeyString) {
    return crypto.subtle.importKey(
        "raw",
        hmacKeyString,
        {
            name: "HMAC",
            hash: {name:  "SHA-512"}
        },
        true,
        ["sign", "verify"]
    );
}

function postNewSessionKey(senderField, sender_Enc_String, recipientField, recipient_Enc_String, HMACKeyString, iV) {
    var sessionKeys = {
         [senderField]: sender_Enc_String,
         [recipientField]: recipient_Enc_String,
         hmacKeyString : HMACKeyString,
         iv : iV
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

async function generateEnc_PKSK(publicKeyString, sessionKeyRaw) {

    const publicKeyObj = await importRSAKey(publicKeyString);
    // console.log(typeof publicKeyObj);

    const enc_String = await encryptString(publicKeyObj, sessionKeyRaw);
    // console.log(enc_String);
    if (enc_String == null){
        
        return null;
    }
    else{
        return convertArrayBufferToBase64(enc_String);
    }
}

async function generateDec_PKSK(privateKeyString, enc_PKSK) {
    const privateKeyObj = await importPrivateKey(privateKeyString);

    const dec_sessionKeyRaw = await decryptString(privateKeyObj, enc_PKSK);

    if (dec_sessionKeyRaw == null){
        console.log("Decryption failed");
        return null;
    }
    else{
        return dec_sessionKeyRaw;
    }
}

async function importRSAKey(stringKey) {
    const binaryDerString = window.atob(stringKey);
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

function importPrivateKey(stringKey){
    const binaryDerString = window.atob(stringKey);
    const binaryDer = str2ab(binaryDerString);

    return window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
}

async function exportCryptoKey(key) {
    // console.log("Session Key before: " + key);
  const exported = await window.crypto.subtle.exportKey(
    "raw",
    key
  );
  const exportedKeyBuffer = new Uint8Array(exported);

  const keyString = `[${exportedKeyBuffer}]`;
  // console.log("Session Key after: " + keyString);
  // console.log("Session Key after: " + typeof keyString);
  return keyString;
}

function importSessionKeyObject(rawKey){
    // const utf8Key = window.crypto.getRandomValues(new Uint8Array(16));

    return window.crypto.subtle.importKey(
    "raw",
    rawKey,
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

function encryptStringAES(key, string, iv){
    var encoded = encodeString(string);

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

function decryptString(key, encrypted){
    return crypto.subtle.decrypt(
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

function decodeString(string) {
    var decoder = new TextDecoder("utf-8");
    return decoder.decode(string);
}

// Set for Message Window
if (sessionStorage.getItem("currentUser") != null && document.getElementById("fromLabel") != null) {
    // console.log("fromLabel: exists");
    // document.getElementById("fromLabel").textContent = "From: " + getCookie("currentUser");
    document.getElementById("fromLabel").textContent = "From: " + sessionStorage.getItem("currentUser");


}

function msg_window_OnLoad(){
    checkLogin();
    // console.log("On load");

    retrieveMessages();
}

async function retrieveMessages(){
    // console.log(getCookie("currentUser"));
    // var messagesData = await getMessages(getCookie("currentUser"));
    var messagesData = await getMessages(sessionStorage.getItem("currentUser"));


    // console.log("run");
    if (messagesData != null){

        const msgPanel = document.getElementById("receivedMsgsPanel");
        const msgTemplate = document.getElementById("messageTemplate");

        for (let i = 0; i < messagesData.length; i++) {
            var processedMsg = await processMessage(messagesData[i]);
            if (processedMsg == null){
                return;
            }

            const sender = messagesData[i][0];
            const recipient = messagesData[i][1];

            const message = processedMsg[0];
            const timestamp = processedMsg[1];
            const time = new Date(parseInt(timestamp, 10)).toLocaleString();
            // console.log(`Message[${time}]: ${message}`);

            const msgClone = createMessageClone(msgTemplate, sender, time);
            msgClone.addEventListener("click", () => {
                viewSelectedMessage(sender, recipient, message);
            });

            msgPanel.appendChild(msgClone);
        }

    }

}

// Views message
function viewSelectedMessage(sender, recipient, message) {
    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "none";

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "block";

    document.getElementById("msgView_From").innerHTML = sender;
    document.getElementById("msgView_To").innerHTML = recipient;
    document.getElementById("msgView_Message").innerHTML = message;
    // messageContainer.children[0].innerHTML = sender;
    // messageContainer.children[1].innerHTML = recipient;
    // messageContainer.children[2].innerHTML = message;
}

function createMessageClone(msgTemplate, sender, time) {
    const msgClone = msgTemplate.cloneNode(true);
    msgClone.removeAttribute('id');
    msgClone.children[0].innerHTML = sender;
    msgClone.children[1].innerHTML = time;
    return msgClone;
}

async function processMessage(msgData) {

    var sender = msgData[0];
    var recipient = msgData[1];
    var enc_msg = msgData[2];
    var mac_enc_msg_ts = msgData[3];

    // Verify HMAC
    let DBsessionKeyDict = await getSessionKey(sender, recipient);
    if (DBsessionKeyDict == null){
        console.error("Session key could not be retrieved");
        return null;
    }

    // Process session key
    var PKSKString;
    if (DBsessionKeyDict["sender"] === sender){
        PKSKString = DBsessionKeyDict["sender_enc"]
    }
    else if (DBsessionKeyDict["recipient"] === sender){
        PKSKString = DBsessionKeyDict["recipient_enc"]
    }

    var sessionKeyAB = await generateDec_PKSK(localStorage.getItem(sender), convertBase64ToArrayBuffer(PKSKString));

    var sessionKeyObj = await importSessionKeyObject(sessionKeyAB);

    // Get HMAC Key Object
    let HMACKey = await generateHMACKeyObject(encodeString(DBsessionKeyDict["hmac"]));
    if (HMACKey == null) {
        console.error("HMAC generation failed");
        return;
    }

    // Get MAC Signature
    MACsignature = convertBase64ToArrayBuffer(mac_enc_msg_ts);

    // Decrypt message
    var verifyStatus = await verifyHMAC(HMACKey, MACsignature, convertBase64ToArrayBuffer(enc_msg));
    if (verifyStatus){
        var decryptedMessageTS = await decryptMessage(sessionKeyObj, convertBase64ToArrayBuffer(enc_msg), convertBase64ToArrayBuffer(DBsessionKeyDict["iv"]));
        var decodedMessageTS = decodeString(decryptedMessageTS);

        // Split message and timestamp
        var message = decodedMessageTS.substring(0, decodedMessageTS.length - 13);
        var timestamp = decodedMessageTS.slice(-13);
        return [message, timestamp];
    }
    else{
        console.error("Verification of message failed!");
        return;
    }
}

function decryptMessage(sessionKeyObj, enc_msg, iv) {
    return window.crypto.subtle.decrypt(
    {
        name: "AES-GCM",
        iv: iv
    },
    sessionKeyObj,
    enc_msg
    )
    .catch((error) => {
        console.error('Error: ', error);
    });
}

function verifyHMAC(key, signature, encoded) {
    return window.crypto.subtle.verify(
        "HMAC",
        key,
        signature,
        encoded
    );
}

function getMessages(target){
    var recipientTar = {
         recipient: target,
    };

    return fetch('/post_getMessages', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(recipientTar),
    })
    .then(response => response.json())
    .then(returnData => {
        if ("messages" in returnData) {
            messagesData = returnData["messages"];
            return messagesData;
        }
        else if ("error" in returnData) {
            return null;
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
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
            var sessionKeyEntryDict = {
                sender: retData["sessionKeyEntry"][0],
                sender_enc: retData["sessionKeyEntry"][1],
                recipient: retData["sessionKeyEntry"][2],
                recipient_enc: retData["sessionKeyEntry"][3],
                hmac: retData["sessionKeyEntry"][4],
                iv: retData["sessionKeyEntry"][5],
            };

            return sessionKeyEntryDict;
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
    // console.log("Cookies: " + document.cookie);
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

function convertBase64ToArrayBuffer(base64) {
    var bin_string = window.atob(base64);
    var len = bin_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++){
        bytes[i] = bin_string.charCodeAt(i);
    }
    return bytes.buffer;
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
