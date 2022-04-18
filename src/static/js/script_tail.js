// class User{
//     constructor(){
//
//     }
// }

var keyPair;

function generateRSAKeyPair(){
    // let keyPair = await window.crypto.subtle.generateKey(
    crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    ).then (function(keyOrKeyPair){
        keyPair = keyOrKeyPair;
    });
}

function encryptString(string){
    var encoded = encodeString(string);

    return crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP'
        },
        key,
        encoded
    );
}

function validateLogin(){
    let x = document.forms["loginForm"]["username"].value;
    let y = document.forms["loginForm"]["password"].value;
    if (x == "" || y == ""){
        alert("Error: One or more textfields empty");
        return false;
    }
}

document.forms['registerForm'].addEventListener('submit', (event)=> {
    event.preventDefault();
    console.log("Register");


    fetch(event.target.action, {
        method: 'POST',
        body: new URLSearchParams(new FormData(event.target))
    }).then((resp) => {
        return resp.json();
    }).then((body) => {
        // TODO handle body
        console.log("Body");
    }).catch((error) => {
        // TODO handle error
        console.log("Error");
    })

    console.log("Cookies: " + document.cookie);
})

function register(){

}
function myFunction(){
    var inputVal = document.getElementById("msgTextField").value;

    alert(inputVal);
}
