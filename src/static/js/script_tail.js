var keyPair;

checkLogin();
runHeaderFunctions();

/* -----------------------------------------------------------------------------
                                 Header
 -----------------------------------------------------------------------------*/
function runHeaderFunctions() {
    setNavLinkTriggers();
    setLoginLogoutButton();
}

function setNavLinkTriggers() {
    const forumLink = document.getElementById("forumLink");
    const messageLink = document.getElementById("messageLink");

    if (window.location.href.match('forums')) {
        forumLink.style.borderBottom = "2px solid #6399D1";
        messageLink.style.borderBottom = "none";
    }
    else if (window.location.href.match('msg_window')) {
        messageLink.style.borderBottom = "2px solid #6399D1";
        forumLink.style.borderBottom = "none";
    }
}

function setLoginLogoutButton() {
    const loginLogoutButton = document.getElementById("loginLogoutButton");
    if (sessionStorage.getItem("currentUser") === ""){
        loginLogoutButton.innerHTML = "Login";
        loginLogoutButton.addEventListener("click", toLogin);
    }
    else {
        loginLogoutButton.innerHTML = "Logout";
        loginLogoutButton.removeEventListener("click", toLogin);
        loginLogoutButton.addEventListener("click", logout);
    }
}

function toLogin() {
    window.location.href = "/login";
}

function logout() {
    sessionStorage.setItem("currentUser", "");
    window.location.href = "/home";
}


/* -----------------------------------------------------------------------------
                                Home Page
 -----------------------------------------------------------------------------*/
function toForums() {
    console.log("Set up to forums requried");
    window.location.href = "/forums";
}

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
               document.getElementById("registerInfo").style.color = "green";
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
    if (!window.location.href.match('login') && !window.location.href.match('register') && !window.location.href.match('home') && !window.location.href.match(new RegExp("^" + 'https:\/\/127.0.0.1:8081\/' + "$", "i"))) {
        if (sessionStorage.getItem("currentUser") == null){
            window.location.href = "/login";
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
/*  ------------------------------- Friends List Panel -------------------------------*/
async function loadFriends(friendsListArray) {
    var friendsList;
    if (friendsListArray == null) {
        const retrievedfriendsList = await getFriendsList(sessionStorage.getItem("currentUser"));

        friendsList = retrievedfriendsList.split(";");
    }
    else {
        friendsList = friendsListArray;
    }
    // console.log(friendsList);


    const friendsListPanel = document.getElementById("friendsList");
    const friendTemplate = document.getElementById("friendTemplate");

    // Clear existing friends list
    var i = 0;
    var friendsPanelChildren = friendsListPanel.children;

    while (i < (friendsListPanel.children).length) {
        if ( !(friendsPanelChildren[i].hasAttribute('id')) ){
            friendsListPanel.removeChild(friendsPanelChildren[i]);
        }
        else {
            i++;
        }
    }
    
    var friendDict = {};

    for (const friend of friendsList) {
        // console.log("Appending : " + friend);
        var profileInt = 0;
        if (!(friend in friendDict)){
            friendDict[friend] = getRandomInt(5);
        }
        profileInt = friendDict[friend];
        
        
        const friendClone = createFriendClone(friendTemplate, profileInt, friend);
        friendClone.addEventListener("click", () => {
            viewNewMessage(friend);
        });

        friendsListPanel.appendChild(friendClone);
    }
}

function createFriendClone(friendTemplate, profileInt, friend) {
    const friendClone = friendTemplate.cloneNode(true);
    friendClone.removeAttribute('id', "friendTemplate");

    const friendProfile = friendClone.querySelector('.profileIcons');
    friendProfile.src = getRandomProfileIcon(profileInt);

    const friendText = friendClone.querySelector('.friendText');
    const friendName = friendText.children[0];
    friendName.innerHTML = friend;
    return friendClone;
}

async function addFriend() {
    const friendTextField = document.getElementById("friendTextField");
    const friendName = friendTextField.value;
    friendTextField.classList.remove("successInputBox");
    friendTextField.classList.remove("errorInputBox");

    // Check if input empty
    if (!friendName) {
        alert("Please enter a username.");
        return;
    }

    // Checks if user exists
    const publicKey = await getPublicKey(friendName);
    if (publicKey == null) {
         alert("Username " + friendName + " not found.");
         friendTextField.classList.add("errorInputBox");
         return;
    }

    // Checks if friend name is friend already
    const curFriendsList = await getFriendsList(sessionStorage.getItem("currentUser"));

    const friendsListArray = curFriendsList.split(";");
    if (friendsListArray.includes(friendName)) {
        // console.log("Already exists");
        return;
    }

    if (postAddFriend(sessionStorage.getItem("currentUser"), friendName)) {
        friendTextField.value = "";
        friendTextField.classList.remove("successInputBox");
        
        // Update friends list
        friendsListArray.push(friendName);
        loadFriends(friendsListArray);
    }   
}

/*  ------------------------------- Message Panel -------------------------------*/
// Views container to send messages
function viewNewMessage(recipient) {

    removeSelectedMessageHighlight();

    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "block";

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "none";

    var senderField = document.getElementById("senderField");
    senderField.textContent = "From: " + sessionStorage.getItem("currentUser");
    if (!(recipient === null)) {
        document.getElementById("recipientField").value = recipient + ";";
    }
}

function catchInputSubmit() {
    var recipientField = document.getElementById("recipientField");
    recipientField.addEventListener("keypress", function(event) {
        if (event.key === "Enter") {
            console.log("Caught?");
            event.preventDefault();
        }
    });
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
    var msgField = document.getElementById("msgTextField").innerHTML;

    const recipientFieldArray = recipientField.split(/; |;/);
    var i = 0;
    while (i < recipientFieldArray.length) {
        if (recipientFieldArray[i] === "") {
            recipientFieldArray.splice(i, 1);
        }
        else {
            ++i;
        }
    }

    if (recipientFieldArray.length == 0) {
        document.getElementById("recipientError").textContent = "Please add at least one valid person and try again.";
        setInfoColours("infoInform");
        return;
    }

    var failedRecipients = [];

    for (const recpt of recipientFieldArray) {
        const recipient_publicKey = await getPublicKey(recpt);
        if (recipient_publicKey == null) {
            failedRecipients.push(recpt);
        }
    }

    if (failedRecipients.length == 0) {
        for (const recpt of recipientFieldArray) {
            sendMessageEncryption(senderField, recpt, msgField);
        }
    
        document.getElementById("recipientError").innerHTML = "Message Sent!";
        console.log(document.getElementById("recipientError").innerHTML);
        // document.getElementById("msgTextField").innerHTML = "";
        setInfoColours("infoSuccess");    
    }
    else {
        document.getElementById("recipientError").textContent = "One or more usernames not found";
        setInfoColours("infoError");
    }

    
}

async function sendMessageEncryption(senderField, recipientField, msgField) {
    // Generates session key if needed
    await sessionKeyHelper(senderField, recipientField);

    // Retrieves session key
    let DBsessionKeyDict = await getSessionKey(senderField, recipientField);

    if (DBsessionKeyDict == null){
        console.log("Session key could not be retrieved");
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

    // console.log("sessionKeyAB type: " + sessionKeyAB);
    var sessionKeyAB = await generateDec_PKSK(localStorage.getItem(senderField), convertBase64ToArrayBuffer(PKSKString));
    
    let sessionKeyObj = await importSessionKeyObject(sessionKeyAB);

    iv = convertBase64ToArrayBuffer(DBsessionKeyDict["iv"]);
    
    let encryptedMessage = await encryptStringAES(sessionKeyObj, msgstamp, iv);
    // console.log(typeof encryptedMessage);
    
    // console.log(DBsessionKeyDict["hmac"]);
    let HMACKey = await generateHMACKeyObject(encodeString(DBsessionKeyDict["hmac"]));

    if (HMACKey == null) {
        // console.log("hmac failed");
        return 0;
    }
    //
    //
    let MACsignature = await window.crypto.subtle.sign(
        "HMAC",
        HMACKey,
        encryptedMessage
    );
    // document.getElementById("recipientError").textContent= "";

    postNewMessage(senderField, recipientField, convertArrayBufferToBase64(encryptedMessage), convertArrayBufferToBase64(MACsignature));
    
    lastMessageTime = Date.now();

    return;
}

function postNewMessage(senderField, recipientField, enc_Message, sig) {

    // console.log("Posting");
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
        // document.getElementById("recipientError").textContent = "";
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
            setInfoColours("infoError");
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

function setInfoColours(infoStatus) {
    if (infoStatus.match("infoError")) {
        document.getElementById("recipientError").classList.remove("infoSuccess");
        document.getElementById("recipientError").classList.remove("infoInform");
        document.getElementById("recipientError").classList.add("infoError");
    }
    else if (infoStatus.match("infoSuccess")) {
        document.getElementById("recipientError").classList.remove("infoError");
        document.getElementById("recipientError").classList.remove("infoInform");
        document.getElementById("recipientError").classList.add("infoSuccess");
    }
    else if (infoStatus.match("infoInform")) {
        document.getElementById("recipientError").classList.remove("infoError");
        document.getElementById("recipientError").classList.remove("infoSuccess");
        document.getElementById("recipientError").classList.add("infoInform");
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
        // console.log("Decryption failed");
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
  const exported = await window.crypto.subtle.exportKey(
    "raw",
    key
  );
  const exportedKeyBuffer = new Uint8Array(exported);

  const keyString = `[${exportedKeyBuffer}]`;
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
    document.getElementById("fromLabel").textContent = "From: " + sessionStorage.getItem("currentUser");
}

function msg_window_OnLoad(){
    checkLogin();
    loadFriends(null);
    
    document.getElementById("senderField").textContent = "From: " + sessionStorage.getItem("currentUser");
    // selectedMessage = null;
    retrieveMessages();
}

async function retrieveMessages(){
    // var messagesData = await getMessages(getCookie("currentUser"));
    var messagesData = await getMessages(sessionStorage.getItem("currentUser"));

    if (messagesData != null){
        const msgPanel = document.getElementById("receivedMsgsPanel");
        const msgTemplate = document.getElementById("messageTemplate");
        
        var mDataLen = messagesData.length;

        var senderDict = {};

        for (var i = mDataLen - 1; i >= 0; i--) {
            var processedMsg = await processMessage(messagesData[i]);
            if (processedMsg == null){
                return;
            }

            const sender = messagesData[i][0];
            const recipient = messagesData[i][1];

            var profileInt = 0;
            if (!(sender in senderDict)){
                senderDict[sender] = getRandomInt(5);
            }
            profileInt = senderDict[sender];

            const message = processedMsg[0];
            const timestamp = processedMsg[1];
            const time = new Date(parseInt(timestamp, 10)).toLocaleString();
            
            const timestampDate = new Date(parseInt(timestamp, 10));
            const currentDate = new Date();

            const dateDiff = Math.abs(timestampDate.getTime() - currentDate.getTime());
            const hoursDiff = dateDiff / (60 * 60 * 1000);
            console.log(timestamp);
            var timeFiltered;
            if (hoursDiff < 24) {
                // console.log("Date within 24 hours");
                timeFiltered = time.split(",")[1];
            }
            else {
                // console.log("Date over 24 hours");
                timeFiltered = time.split(",")[0];
            }



            const msgClone = createMessageClone(msgTemplate, sender, timeFiltered, message, profileInt);
            msgClone.addEventListener("click", () => {
                removeSelectedMessageHighlight();
                viewSelectedMessage(msgClone, sender, recipient, message, time, profileInt);
            });

            msgPanel.appendChild(msgClone);
        }

    }

}

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

// Views message
function viewSelectedMessage(msgClone, sender, recipient, message, time, profileInt) {
    msgClone.setAttribute('id', 'messageBoxSelected');
    
    var inputContainer = document.getElementById("msgInputContainer");
    inputContainer.style.display = "none";

    var messageContainer = document.getElementById("msgViewContainer");
    messageContainer.style.display = "block";

    document.getElementById("msgView_From").innerHTML = sender;
    document.getElementById("msgView_To").innerHTML = "To: " + recipient;
    document.getElementById("msgView_Message").innerHTML = message;
    document.getElementById("msgView_Time").innerHTML = time;
    document.getElementById("senderProfileIcon").src = getRandomProfileIcon(profileInt);
}

function removeSelectedMessageHighlight() {
    const curSelectedMessage = document.getElementById("messageBoxSelected");
    if (curSelectedMessage != null) {
        curSelectedMessage.removeAttribute('id', 'messageBoxSelected');        
    }
}

function createMessageClone(msgTemplate, sender, time, message, profileInt) {
    const msgClone = msgTemplate.cloneNode(true);
    msgClone.removeAttribute('id', "messageTemplate");

    const messageProfile = msgClone.querySelector('.profileIcons');
    messageProfile.src = getRandomProfileIcon(profileInt);

    const messageText = msgClone.querySelector('.messageText');
    const senderTime = messageText.children[0];
    senderTime.children[0].innerHTML = sender;
    senderTime.children[1].innerHTML = time;
    messageText.children[1].innerHTML = message;
    return msgClone;
}

function getRandomProfileIcon(profileInt) {
    const colours = ["blue", "green", "grey", "orange", "red"];
    return "/img/profile_icons/" + colours[profileInt] + ".png";
}

async function processMessage(msgData) {

    var sender = msgData[0];
    var recipient = msgData[1];
    var enc_msg = msgData[2];
    var mac_enc_msg_ts = msgData[3];

    // Verify HMAC
    let DBsessionKeyDict = await getSessionKey(sender, recipient);
    if (DBsessionKeyDict == null){
        // console.error("Session key could not be retrieved");
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
                                Forums
 -----------------------------------------------------------------------------*/
 async function forumsWindowOnLoad() {
    var currentForum = await retrieveForums(null);
    localStorage.setItem('currentForum', currentForum)
    loadPostsAndRightPanel();
}

async function getPosts(forum_id) {
    console.log("here is it: " + forum_id);
    var forum_id_data = {
        forum_id: forum_id,
    };
   return fetch('/get_posts', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(forum_id_data),
   })
   .then(response => response.json())
   .then(returnData => {
       if ("posts" in returnData) {
           posts = returnData["posts"];
           return posts;
       }
       else if ("error" in returnData) {
           return null;
       }
   })
   .catch((error) => {
       console.error('Error: ', error);
   });
}

function createPostClone(postTemplate, author, time, title, tags) {
    const postClone = postTemplate.cloneNode(true);
    postClone.removeAttribute('id', "postTemplate");
    postClone.style.display = "flex";
    console.log(postClone);
    const tagList = postClone.querySelector('.tagList')
    for (var i = 0; tagList.children.length != 1; i++) {
        tagList.removeChild(tagList.children[0]);
    }
    // tagList.children[0].style.display = 'none';

    //var postsParent = document.getElementById('postList');
    // for (var i = 0; postsParent.children.length != 2; i++) {
    //     postsParent.removeChild(postsParent.children[1]);
    // }
    // postsParent.children[1].style.display = 'none';
    const titleText = postClone.querySelector('.postTitle');
    const picNameTimestamp = postClone.querySelector('.picNameTimestamp');
    console.log(titleText);
    var tag = tagList.querySelector('.tag_button');
    tag.setAttribute('id', 'tag');
    if (tags != null) {
        for (var i = 0; i < tags.length; i++) {
            tagClone = tag.cloneNode(true);
            tagClone.removeAttribute('id', 'tag');
            tagClone.textContent = tags[i];
            tagList.appendChild(tagClone);
        }
    }
    titleText.textContent = title;
    picNameTimestamp.children[1].innerHTML = author;
    picNameTimestamp.children[2].innerHTML = time;
    return postClone;
}

function getTags(post_id) {
    var post_id_data = {
        post_id: post_id,
   };

   return fetch('/get_tags', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(post_id_data),
   })
   .then(response => response.json())
   .then(returnData => {
       if ("tags" in returnData) {
           tags = returnData["tags"];
           console.log(tags);
           return tags;
       }
       else if ("error" in returnData) {
           return null;
       }
   })
   .catch((error) => {
       console.error('Error: ', error);
   });
}

function updateHighlight(toHighlight) {
    forums = document.getElementsByClassName('forumBox');
    for (var i = 0; i < forums.length; i++) {
        forums[i].style.backgroundColor = 'white';
    }
    toHighlight.style.backgroundColor = '#bde4ff';
}

function removeSubscriptionClick(element) {
    var forumsParent = element.parentNode;
    // TODO
}

function removeVisiblePostsFromUI() {
    var postsParent = document.getElementById('postList');
    for (var i = 0; postsParent.children.length != 2; i++) {
        postsParent.removeChild(postsParent.children[1]);
    }
    postsParent.children[1].style.display = 'none';
}

async function forumClick(element) {
    updateHighlight(element);
    // await removeVisiblePostsFromUI()
    // loadPosts()
    // console.log('forums loaded');
}

async function createCommentClone(commentTemplate, comment, author, time, profileInt) {
    console.log('thisiscomment template: ');
    console.log(commentTemplate); 
    const commentClone = commentTemplate.cloneNode(true);
    commentClone.removeAttribute('id', "commentTemplate");
    commentClone.setAttribute('display', "block");
    const messageProfile = commentClone.querySelector('.profileIcons');
    messageProfile.src = getRandomProfileIcon(profileInt);
    const picNameTime = commentClone.querySelector('.picNameTimestamp');
    const commentText = commentClone.querySelector('.infoDesc');
    picNameTime.children[1].innerHTML = author;
    picNameTime.children[2].innerHTML = time;
    commentText.innerHTML = comment;
    console.log('this is cmtclone');
    console.log(commentClone);
    return commentClone;
}

async function retrieveComments() {
        var commentsData = await getComments(sessionStorage.getItem("selectedPost"));
        console.log('comments are');
        console.log(commentsData);
        if (commentsData != null){
            const commentsPanel = document.getElementById("commentContainer");
            commentsPanel.style.display = flex;
            const commentTemplate = document.getElementById("commentTemplate");
            for (var i = commentsData.length - 1; i >= 0; i--) {
                var post_id = commentsData[i][0];
                var author = commentsData[i][1];
                var body = commentsData[i][2];
                var ts = commentsData[i][3];
                const time = new Date(parseInt(ts, 10)).toLocaleString();
                const currentDate = new Date();
                const timestampDate = new Date(parseInt(ts, 10));
                const dateDiff = Math.abs(timestampDate.getTime() - currentDate.getTime());
                const hoursDiff = dateDiff / (60 * 60 * 1000);
                
                var timeFiltered;
                if (hoursDiff < 24) {
                    timeFiltered = time.split(",")[1];
                }
                else {
                    timeFiltered = time.split(",")[0];
                }
                
                const commentClone = await createCommentClone(commentTemplate, body, author, timeFiltered, 1);
                commentsPanel.appendChild(commentClone);
                
                // postClone.addEventListener("click", () => {
                //     document.getElementById('selectedPostTitle').textContent = title;
                //     document.getElementById('selectedPostAuthor').textContent = author;
                //     document.getElementById('selectedPostTime').textContent = time;
                //     document.getElementById('postMessage').textContent = body;
                //     sessionStorage.setItem('selectedPost', post_id);
                //     retrieveComments();
                // });
            }
        }
}

async function loadPostsAndRightPanel() {
    // var messagesData = await getMessages(getCookie("currentUser"));
    console.log('we good? ');
    console.log(localStorage.getItem('currentForum'));
    var postsData = await getPosts(localStorage.getItem("currentForum"));
    console.log(postsData);
    console.log('hmm');
    var forumNameLabel = document.getElementById('info_panel_title');
    forumNameLabel.textContent = await getForumName(localStorage.getItem('currentForum'));
    var forumDescriptionLabel = document.getElementById('forum_description');
    forumDescriptionLabel.textContent = await getForumDescription(localStorage.getItem('currentForum'));
    var forumCodeLabel = document.getElementById('forum_code');
    forumCodeLabel.textContent = localStorage.getItem("currentForum");
    var forumAdminLabel = document.getElementById('admin');
    forumAdminLabel.textContent = await getForumAdmin(localStorage.getItem('currentForum'));
    if (postsData != null){
        const postsPanel = document.getElementById("postList");
        const postTemplate = document.getElementsByClassName("postBox")[0];
        for (var i = postsData.length - 1; i >= 0; i--) {
            var post_id = postsData[i][0];
            var forum_id = postsData[i][1];
            var author = postsData[i][2];
            var title = postsData[i][3];
            var body = postsData[i][4];
            var ts = postsData[i][5];
            
            // var profileInt = 0;
            // if (!(sender in senderDict)){
            //     senderDict[sender] = getRandomInt(5);
            // }
            // profileInt = senderDict[sender];
            
            const time = new Date(parseInt(ts, 10)).toLocaleString();
            const currentDate = new Date();
            const timestampDate = new Date(parseInt(ts, 10));
            const dateDiff = Math.abs(timestampDate.getTime() - currentDate.getTime());
            const hoursDiff = dateDiff / (60 * 60 * 1000);
            
            var timeFiltered;
            if (hoursDiff < 24) {
                timeFiltered = time.split(",")[1];
            }
            else {
                timeFiltered = time.split(",")[0];
            }
            var tags = await getTags(post_id);
            console.log(postTemplate);
            const postClone = createPostClone(postTemplate, author, timeFiltered, title, tags);
            postsPanel.appendChild(postClone);
            
            postClone.addEventListener("click", async () => {
                document.getElementById('selectedPostTitle').textContent = title;
                document.getElementById('selectedPostAuthor').textContent = author;
                document.getElementById('selectedPostTime').textContent = time;
                document.getElementById('postMessage').textContent = body;
                sessionStorage.setItem('selectedPost', post_id);
                await retrieveComments();
            });
        }
    }
}

function createForumClone(forumTemplate, forumName, highlighted) {
    const forumClone = forumTemplate.cloneNode(true);
    forumClone.removeAttribute('id', "forumTemplate");
    if (highlighted) forumClone.style.backgroundColor = '#bde4ff';
    const forumText = forumClone.querySelector('.forumText');
    forumText.children[0].innerHTML = forumName;
    return forumClone;
}

async function unloadForums() {
    // TODO
}

async function retrieveForums(user, currentForum) {
    var forumIDs = await getForums(user);
    if (forumIDs != null) {
        if (currentForum == null) currentForum = forumIDs[0];
        const forumPanel = document.getElementById('forumsList');
        const forumTemplate = document.getElementById('forumTemplate');
        if (forumTemplate == null) return;
        for (var i = 0; i < forumIDs.length; i++) {
            console.log(forumIDs[i]);
            console.log(getForumName(forumIDs[i]))
            console.log('\n');
            forumName = await getForumName(forumIDs[i]);
            if (forumName == null) continue;
            const forumClone = createForumClone(forumTemplate, forumName, forumIDs[i] == currentForum);
            forumPanel.appendChild(forumClone);
            const j = i; // for some reason the following lambda can't access i directly, hence this line
            forumClone.addEventListener("click", () => {
                localStorage.setItem('currentForum', forumIDs[j]);
                removeVisiblePostsFromUI()
                loadPostsAndRightPanel()
                console.log('forums loaded');
            });
        }
       
        return forumIDs[0]
    } else {
        console.log('no forums or forums failed to load');
    }
    return null
}

function newPost() {
    console.log('new post function funning');
    var title = document.getElementById('titleField');
    var body = document.getElementById('postTextField');
    var tag = document.getElementById('tagField');
    if (title == null || body == null) {
        console.log("title, body can't be empty [handle]");
        return;
    }
    if (tag == null) createPost(title.value, body.textContent, tag);
    else createPost(title.value, body.textContent, tag.textContent);
}

// Change Between Different Panels on the Post Container
function viewPostPanel(panel) {
    var blockElementId = "";
    const noneElementIds = ["newPostContainer", "allPostContainer", "commentContainer", "selectedPostContainer"];
    switch (panel) {
        case "new":
            blockElementId = "newPostContainer";
            break;
        
        case "all":
            blockElementId = "allPostContainer";
            break;

        case "selected":
            blockElementId = "selectedPostContainer";
            break;

        case "comments":
            blockElementId = "commentContainer";
        
        default:
            console.log("Invalid panel trigger");
    }

    for (const id of noneElementIds) {
        var idElement = document.getElementById(id);
        if (id.match(blockElementId)) {
            idElement.style.display = "block";
        }
        else {
            idElement.style.display = "none";
        }
    }
}

function toggleOverlay(state) {
    switch (state) {
        case "close":
            var idElement = document.getElementById("overlay");
            idElement.style.display = "none";
            break;
        
        case "open":
            var idElement = document.getElementById("overlay");
            idElement.style.display = "block";
            break;
        
        default:
            console.log("Invalid overlay toggle state");
    }
}


/* -----------------------------------------------------------------------------
                                Database Calls.
 -----------------------------------------------------------------------------*/

 function getComments() {
    var comment_data = {
        post_id: sessionStorage.getItem('selectedPost'),
   };
   return fetch('/post_getComments', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(comment_data),
   })
   .then(response => response.json())
   .then(returnData => {
       if ("comments" in returnData) {
           commentsData = returnData["comments"];
           return commentsData;
       }
       else if ("error" in returnData) {
           return null;
       }
   })
   .catch((error) => {
       console.error('Error: ', error);
   });
}

 async function getFriendsList(user) {

    var getFriends = {
         username: user
    };

    return await fetch('/get_friends_list', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(getFriends),
    })
    .then(response => response.json())
    .then(retData => {
        // return retData;
        if ("error" in retData){
            return null;
        }
        else {
            return retData["friendsList"];
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}

async function addComment() {
    var commentElement = document.getElementById('commentTextField');
    if (commentElement == null) return;
    var commentData = {
        comment: commentElement.textContent,
        author: sessionStorage.getItem('currentUser'),
        post_id: sessionStorage.getItem('selectedPost'),
   };
   console.log("SDJFDJSAKFDSDF");
   document.getElementById('commentTextField').textContent = "";
   return await fetch('/add_comment', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(commentData),
   })
   .catch((error) => {
       console.error('Error: ', error);
   });
}

async function postAddFriend(user, friendName) {
    
    var addFriendJson = {
         username: user,
         friend: friendName
    };

    return await fetch('/add_friend', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(addFriendJson),
    })
    .then(response => response.json())
    .then(retData => {
        if ("Status" in retData){
            if (retData["Status"].match("Success")) {
                return true;
            }
            else {
                return false;
            }
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}


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
        if ("error" in retData){
            return null;
        }
        else {
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

async function createPost(title, body, tag) {
    var new_post_data = {
        creator: sessionStorage.getItem("currentUser"),
        title: title,
        body: body,
        tag: tag,
        forum_id: localStorage.getItem('currentForum'),
   };
   console.log("for this new post we have:");
   console.log(new_post_data);
   return fetch('/create_post', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(new_post_data),
   })
   .then(response => response.json())
   .then(returnData => {
       if ("post_id" in returnData) {
           console.log("post id: " + returnData['post_id']);
       }
       else if ("error" in returnData) {
           console.log('sad1');
           return null;
       }
   })
   .catch((error) => {
       console.error('Error: ', error);
       console.log('sad2');
   });
}

async function clickSubscribe() {
    let forum_id = document.getElementById("forumTextField").value;
    var forum_id_data = {
        forum_id: forum_id,
        subscriber: sessionStorage.getItem("currentUser"),
    };

    fetch('/subscribe', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(forum_id_data),
    })
    .then(response => response.json())
    .then(retData => {
        if (retData["ret"] == -1){ 
            document.getElementById("subscribeInfo").textContent = "Invalid forum code";
            document.getElementById("subscribeInfo").style.color = "red";
            document.getElementById("forumTextField").value = "";
        }
        else if (retData["ret"] == 1) {
            document.getElementById("subscribeInfo").style.color = "green";
            document.getElementById("subscribeInfo").textContent = "Subscription successful";
            document.getElementById("forumTextField").value = "";
        } 
        else if (retData["ret"] == 0) {
            document.getElementById("subscribeInfo").textContent = "Already subscribed";
            document.getElementById("subscribeInfo").style.color = "orange";
            document.getElementById("forumTextField").value = "";
        }
        else {
            console.log("subscription failed");
            document.getElementById("subscribeInfo").textContent = "Invalid forum code";
            document.getElementById("subscribeInfo").style.color = "red";
            document.getElementById("forumTextField").value = "";
        }
        return retData['ret'];
    })
    .catch((error) => {
        console.error('Error: ', error);
    });
}

async function createForum() {
    var new_forum_data = {
        forumName: document.getElementById('nameField').value,
        desc: document.getElementById('descField').textContent,
        creator: sessionStorage.getItem("currentUser"),
    };
    console.log('whatisthis ');
    console.log(new_forum_data);
    fetch('/create_forum', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(new_forum_data),
    })
    .then(response => response.json())
    .then(returnData => {
        if ("forum_id" in returnData) {
            var forum_id_data = {
                forum_id: returnData["forum_id"],
                subscriber: sessionStorage.getItem("currentUser"),
            };
            fetch('/subscribe', {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/json'
                    },
                    body: JSON.stringify(forum_id_data),
            })
            .catch((error) => {
                console.error('Error: ', error);
            });
            document.getElementById('nameField').value = "";
            document.getElementById('descField').textContent = "";
        }
        else if ("error" in returnData) {
            console.log('sad1');
            return null;
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
        console.log('sad2');
    });

    
 }

function getForums(){
    var user_logged_on = {
         user_logged_in: sessionStorage.getItem("currentUser"),
    };

    return fetch('/post_getForums', {
         method: 'POST',
         headers: {
             'content-type': 'application/json'
         },
         body: JSON.stringify(user_logged_on),
    })
    .then(response => response.json())
    .then(returnData => {
        if ("forum_ids" in returnData) {
            forum_ids = returnData["forum_ids"];
            return forum_ids;
        }
        else if ("error" in returnData) {
            console.log('sad1');
            return null;
        }
    })
    .catch((error) => {
        console.error('Error: ', error);
        console.log('sad2');
    });
}

async function getForumName(forum_id){
    var forum_id_data = {
        forum_id: forum_id,
    };

   const response = await fetch('/post_getForumName', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(forum_id_data),
    });
    const returnData = await response.json();
    if ("forum_name" in returnData) {
        return returnData["forum_name"];
    }
    else if ("error" in returnData) {
        console.log('sad1');
        return null;
    }
}

async function getForumDescription(forum_id){
    var forum_id_data = {
        forum_id: forum_id,
    };

   const response = await fetch('/post_getForumDesc', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(forum_id_data),
    });
    const returnData = await response.json();
    if ("forum_desc" in returnData) {
        return returnData["forum_desc"];
    }
    else if ("error" in returnData) {
        console.log('sad1');
        return null;
    }
}

async function getForumAdmin(forum_id){
    var forum_id_data = {
        forum_id: forum_id,
    };

   const response = await fetch('/post_getForumAdmin', {
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify(forum_id_data),
    });
    const returnData = await response.json();
    if ("forum_admin" in returnData) {
        return returnData["forum_admin"];
    }
    else if ("error" in returnData) {
        console.log('sad1');
        return null;
    }
}

/* -----------------------------------------------------------------------------
                                Misc.
 -----------------------------------------------------------------------------*/

function myFunction(){
    var inputVal = document.getElementById("msgTextField").value;
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
