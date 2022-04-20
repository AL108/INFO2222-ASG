// class User{
//     constructor(){
//
//     }
// }

var keyPair;

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

function encryptString(string){
    var encoded = encodeString(string);

    return crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP'
        },
        publicKey,
        encoded
    );
}

function decryptString(encrypted){
    var decrypt = crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP'
        },
        publicKey,
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

    var messageForm = document.getElementById("sendMessageForm");
    var senderFieldLabel = document.getElementById("senderField").textContent;
    var senderField = senderFieldLabel.replace('From: ', '');
    var recipientField = document.getElementById("recipientField").value;
    var msgField = document.getElementById("msgTextField").value;

    // console.log("sender: " + senderField);
    // console.log("recipient: " + recipientField);
    // console.log("msg: " + msgField);

    // getPublicKey(recipientField);
    let sessionKey = await getSessionKey(senderField, recipientField);

    // Use decrypt encrypted session key to then encrypt a message
    if(sessionKey != null){
        console.log(sessionKey);
        document.getElementById("recipientError").textContent = "";
    }

    // Create session key
    else{
        console.log("Session key with this user not found");

        // Check if user exists first
            // User exists: Create session key

            // Not exist:
                document.getElementById("recipientError").textContent = "Username not found";
    }
}

// Set for Message Window
if (getCookie("currentUser") != null && document.getElementById("fromLabel") != null) {
    console.log("fromLabel: exists");
    document.getElementById("fromLabel").textContent = "From: " + getCookie("currentUser");
}

/* -----------------------------------------------------------------------------
                                Database Calls.
 -----------------------------------------------------------------------------*/

function getPublicKey(user) {

    var getUser = {
         username: user,
    };

    fetch('/get_public_key', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(getUser),
    })
    .then(response => response.json())
    .then(retData => {
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
