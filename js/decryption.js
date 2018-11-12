var clientKey;
var serverKey;

function setPassword(decryptionKey)
{

  function generateServerKey(decryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(decryptionKey);
    //console.log("First Hash: " + firsthash[0].toString(16) + firsthash[1].toString(16) + firsthash[2].toString(16) + firsthash[3].toString(16) + firsthash[4].toString(16) + firsthash[5].toString(16) + firsthash[6].toString(16) + firsthash[7].toString(16));
    console.log("Server First Hash: " + sjcl.codec.hex.fromBits(firsthash));
    var cutkey = sjcl.codec.hex.fromBits(firsthash).substr(0,32);
    console.log("Server Cut Key: " + cutkey);

    var secondhash = sjcl.hash.sha256.hash(decryptionKey + cutkey);
    console.log("Server Second Hash: " + sjcl.codec.hex.fromBits(secondhash));

    var hexsecondhash = sjcl.codec.hex.fromBits(secondhash);

    var generatedKey = new Uint8Array(32);

    for(var i = 0; i < generatedKey.length; i++)
    {
      generatedKey[i] = parseInt(hexsecondhash.substr(i*2,2));

    }

    return generatedKey;


  }

  function generateClientKey(decryptionKey)
  {
    var firsthash = sjcl.hash.sha256.hash(decryptionKey);
    //console.log("First Hash: " + firsthash[0].toString(16) + firsthash[1].toString(16) + firsthash[2].toString(16) + firsthash[3].toString(16) + firsthash[4].toString(16) + firsthash[5].toString(16) + firsthash[6].toString(16) + firsthash[7].toString(16));
    console.log("First Hash: " + sjcl.codec.hex.fromBits(firsthash));
    var cutkey = sjcl.codec.hex.fromBits(firsthash).substr(32,32);
    console.log("Cut Key: " + cutkey);

    var secondhash = sjcl.hash.sha256.hash(decryptionKey + cutkey);
    console.log("Second Hash: " + sjcl.codec.hex.fromBits(secondhash));

    var hexsecondhash = sjcl.codec.hex.fromBits(secondhash);

    var generatedKey = new Uint8Array(32);

    for(var i = 0; i < generatedKey.length; i++)
    {
      generatedKey[i] = parseInt(hexsecondhash.substr(i*2,2));

    }

    return generatedKey;

  }
  clientKey = generateClientKey(decryptionKey);
  serverKey = generateServerKey(decryptionKey);
}

function clientSideDecryption(fileToBeDecrypted)
{
  var reader = new FileReader();
  reader.readAsText(fileToBeDecrypted);
  //reader.readAsBinaryString(fileToBeDecrypted);
  /*
    After the file has been read in, iv is retrieved from the start, deleted from the ciphertext,
    then AES js is used to decrypt the ciphertext.
  */


  reader.onload = function(e)
  {
    var file = reader.result;
    console.log("ok" + file);


    /*
      Algorithm for retrieving the IV from the start of the text file. Will need to be rewritten
      after the data to be decrypted is sent from the output of the steg server instead of an uploaded
      text file, as IV will be stored as a 128 bit object instead of the string representation of an array
    */
    var iv = new Array(16);
    var count = 0;
    var prevcount = 0;
    for(var i = 0; i < 16; i++)
    {
      do
      {
        count++;
      }while(file[count] != ",");

      console.log(file.substring(prevcount, count));
      iv[i] = parseInt(file.substring(prevcount, count));
      prevcount = count + 1;

    }
    file = file.substring(count + 1, file.length);

    /*
      Now I use the same algorithm to convert the remaining ciphertext into a bunch of integers.
    */

    var parsedText = new Array();

    count = 0;
    prevcount = 0;
    var index = 0;
    do
    {
      do
      {
        count++;
      }while(file[count] != "," && count != file.length);

      console.log(file.substring(prevcount, count));
      parsedText[index] = parseInt(file.substring(prevcount, count));
      prevcount = count + 1;
      index++;
    }while(count != file.length);

    console.log(file);
    //var cipherText = aesjs.utils.utf8.toBytes(parsedText);
    console.log(parsedText);
    var aesCbc = new aesjs.ModeOfOperation.cbc(clientKey, iv);

    var decryptedBytes = aesCbc.decrypt(parsedText);
    alert(aesjs.utils.utf8.fromBytes(decryptedBytes));

  }


}
