function takeInput(imageFile, dataToBeEncrypted, encryptionKey)
{
/*Take the input sent from the web page.
Generate 2 keys.
Encrypt it with AES with Key 1.
Send a second key to the connection to the steg server along with the rest of the data to be encrypted.
*/
  /*
    Key generation: Hash encryptionKey with SHA256
    Hash encryptionKey + bits 0-127 with SHA256 again: This is the server side key
    Hash encryptionKey + bits 128-255 with SHA256 again: This is the client side key
  */

  if(typeof(dataToBeEncrypted) == "string")
  {
    while(dataToBeEncrypted.length % 16 != 0)
    {
      dataToBeEncrypted = dataToBeEncrypted + " ";
    }
  }

  function generateServerKey(encryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(encryptionKey);
    //console.log("First Hash: " + firsthash[0].toString(16) + firsthash[1].toString(16) + firsthash[2].toString(16) + firsthash[3].toString(16) + firsthash[4].toString(16) + firsthash[5].toString(16) + firsthash[6].toString(16) + firsthash[7].toString(16));
    console.log("Server First Hash: " + sjcl.codec.hex.fromBits(firsthash));
    var cutkey = sjcl.codec.hex.fromBits(firsthash).substr(0,32);
    console.log("Server Cut Key: " + cutkey);

    var secondhash = sjcl.hash.sha256.hash(encryptionKey + cutkey);
    console.log("Server Second Hash: " + sjcl.codec.hex.fromBits(secondhash));

    var hexsecondhash = sjcl.codec.hex.fromBits(secondhash);

    var generatedKey = new Uint8Array(32);

    for(var i = 0; i < generatedKey.length; i++)
    {
      generatedKey[i] = parseInt(hexsecondhash.substr(i*2,2));

    }

    return generatedKey;

  }

  function generateClientKey(encryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(encryptionKey);
    //console.log("First Hash: " + firsthash[0].toString(16) + firsthash[1].toString(16) + firsthash[2].toString(16) + firsthash[3].toString(16) + firsthash[4].toString(16) + firsthash[5].toString(16) + firsthash[6].toString(16) + firsthash[7].toString(16));
    //console.log("First Hash: " + sjcl.codec.hex.fromBits(firsthash));
    var cutkey = sjcl.codec.hex.fromBits(firsthash).substr(32,32);
    console.log("Cut Key: " + cutkey);

    var secondhash = sjcl.hash.sha256.hash(encryptionKey + cutkey);
    console.log("Second Hash: " + sjcl.codec.hex.fromBits(secondhash));

    var hexsecondhash = sjcl.codec.hex.fromBits(secondhash);

    var generatedKey = new Uint8Array(32);

    for(var i = 0; i < generatedKey.length; i++)
    {
      generatedKey[i] = parseInt(hexsecondhash.substr(i*2,2));

    }

    return generatedKey;

  }

  function generateRandom()
  {
    var random = (Math.random() * 256);

    var randomint = Math.floor(random);

    return randomint;

  }

  serverKey = generateServerKey(encryptionKey);
  clientKey = generateClientKey(encryptionKey);

  var iv = [generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(), generateRandom(),generateRandom(), generateRandom(),generateRandom(), generateRandom()];

  var textBytes = aesjs.utils.utf8.toBytes(dataToBeEncrypted);


  var aesCbc = new aesjs.ModeOfOperation.cbc(clientKey, iv);
  var encryptedFile = aesCbc.encrypt(textBytes);
  //var encryptedHex = aesjs.util.hex.fromBytes(encryptedFile);
  //alert(encryptedHex);

  var newAesCbc = new aesjs.ModeOfOperation.cbc(clientKey, iv);

  //var encryptedBytes = new aesjs.utils.hex.toBytes(encryptedFile);
  var decryptedBytes = newAesCbc.decrypt(encryptedFile);
  alert("Decrypted bytes: " + decryptedBytes);

  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  alert("Decrypted text:" + decryptedText);


  var downloadableFile = new Blob([iv + "," + encryptedFile], {type: "text/plain;charset=utf-8"});
  saveAs(downloadableFile, "cipherText.txt");

  return encryptedFile;
  /*Call encryptdata.php, inputs are serverKey, imageFile, encryptedFile*/

}
