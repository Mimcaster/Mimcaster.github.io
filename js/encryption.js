function takeInput(imageFile, dataToBeEncrypted, encryptionKey)
{
/*Take the input sent from the web page.
Generate 2 keys.
Encrypt it with AES with Key 1.
Send a second key to the connection to the steg server along with the rest of the data to be encrypted.
*/
  /*
    Key generation: Hash encryptionKey with SHA256
    Hash bits 0-127 with SHA256 again: This is the server side key
    Hash bits 128-255 with SHA256 again: This is the client side key
  */

  function generateServerKey(encryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(encryptionKey);
    var cutkey =
    return sjcl.hash.sha256.hash(cutkey);
  }

  function generateClientKey(encryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(encryptionKey);
    var cutkey = firsthash % (2^128);
    return sjcl.hash.sha256.hash(cutkey);

  }
  serverKey = generateServerKey(encryptionKey);
  clientKey = generateClientKey(encryptionKey);

  var aesCipher = sjcl.cipher.aes(clientKey);
  var encryptedFile = sjcl.mode.ccm.encrypt(aesCipher, plaintext, iv);

  /*Call encryptdata.php, inputs are serverKey, imageFile, encryptedFile*/

}
