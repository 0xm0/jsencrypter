var fs = require('fs');
var crypto = require('crypto');
var cmdArgument = process.argv.slice(2);
algorithm = 'aes-256-ctr'; 
var os = require('os');
if (os.platform() == 'win32') {  
    if (os.arch() == 'ia32') {
        var chilkat = require('@chilkat/ck-node12-win-ia32');
    } else {
        var chilkat = require('@chilkat/ck-node12-win64'); 
    }
} 
const readline = require('readline-sync');
function menu(){
	var key = new chilkat.SshKey();

    var success;

    var numBits;
    var exponent
	numBits = 2048;
    exponent = 65537;
    success = key.GenerateRsaKey(numBits,exponent);
    if (success !== true) {
        console.log("Bad params passed to RSA key generation method.");
        return;
    }

    // Note: Generating a public/private key pair is CPU intensive
    // and won't take anything longer than 1 minute to generate.

    var exportedKey;
    var exportEncrypted;
	const { stdin, stdout } = process;

		function prompt(question) {
		return new Promise((resolve, reject) => {
			stdin.resume();
			stdout.write(question);

			stdin.on('data', data => resolve(data.toString().trim()));
			stdin.on('error', err => reject(err));
		});
}
    //cmdArgument[0]  is the first argument - the 1st arg defines what the program is going to do, and so this if is the first layer. 
    if (cmdArgument[0] == "-encrypt" || cmdArgument[0] == "-e"){
        //Checks to see if the password argument is empty = generates one if not.
        if (cmdArgument[2] == null){
            var genPwd = passwordGen(16);
            console.log("No password argument given. Generated & used:", genPwd)
            readFile(cmdArgument[1],"-encrypt", genPwd)
        }else{
            readFile(cmdArgument[1],"-encrypt",cmdArgument[2])
        }
    }else if (cmdArgument[0] == "-decrypt" || cmdArgument[0] == "-d"){
        if (cmdArgument[2] == null){
            console.log("No password argument given. Cannot decrypt. Run node main.js help")
        }else{
            readFile(cmdArgument[1],"-decrypt",cmdArgument[2])
        }
    }else if (cmdArgument[0] == "-password" || cmdArgument[0] == "-p"){
        //isNaN checks if the value is a number, and if it is then it sends that value to gen, If not, uses the default length of 16
        if (isNaN(cmdArgument[1]) == false){
            console.log("Password Generated:", passwordGen(cmdArgument[1]))
        }else{
            console.log("Password Generated at the default length of 16:", passwordGen(16))
        }
    }else if (cmdArgument[0] == "-help" || cmdArgument[0] == "-h"){
        //gives detailed help
        
		console.log("JS VU Encrypter - © 0xm0 ")
		console.log("Please run one of the options:")
		console.log("1) Encrypt a file [ node main.js -e,-encrypt filename.ext optional_password ]")
		console.log("2) Decrypt a file [ node main.js -d,-decrypt filename.ext password ] ")
		console.log("3) Generate an unencrypted PuTTY RSA private key [3]")
		console.log("4) Generate an encrypted RSA OpenSSH Private Key [4] ")
		console.log("5) Generate an RSA private key to unencrypted PuTTY format [5]")
		console.log("6) Generate an RSA private key to encrypted PuTTY format [6]")
		console.log("7) Generate private key to XML [7]")
		console.log("8) Generate Secure Shell (SSH) Public Key File Format (RFC 4716) [8]")
		console.log("9) Generate Secure Shell (SSH) Public Key File Format (OpenSSH) [9]")
		console.log("10) Quit Program [10]")
		
    }else if (cmdArgument[0] == "3" || cmdArgument[0] == "3"){
		var secretkey3 = 0;
		secretname3 = readline.question(`Please enter a file name: \n`);
		if (fs.existsSync(secretkey3 + ".pem")) {
			console.log("File already exists")
			process.exit()

		}
		exportEncrypted = false;
		exportedKey = key.ToOpenSshPrivateKey(exportEncrypted);
		success = key.SaveText(exportedKey,"privkey_putty_unencrypted.pem");
		fs.renameSync('privkey_putty_unencrypted.pem', secretname3 + '.pem');
		
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "4" ){
		
		var secretkey4 = 0;
		secretkey4 = readline.question(`Please enter a secret key: \n`);
		secretname4 = readline.question(`Please enter a file name: \n`);
		key.Password = secretkey4
		if (fs.existsSync(secretkey4 + ".pem")) {
			console.log("File already exists")
			process.exit()

		}
		console.log("The key " + secretkey4 + " has been saved to file " + secretname4 + ".pem");
		exportEncrypted = true;
		exportedKey = key.ToOpenSshPrivateKey(exportEncrypted);
		success = key.SaveText(exportedKey,"privkey_openssh_encrypted.pem");
		fs.renameSync('privkey_openssh_encrypted.pem', secretname4 + '.pem');
		console.log('Key Saved to: ' + process.cwd());
		
    }else if (cmdArgument[0] == "5" ){
		var secretkey5 = 0;
		secretname5 = readline.question(`Please enter a file name: \n`);
		if (fs.existsSync(secretkey5 + ".ppk")) {
			console.log("File already exists")
			process.exit()

		}
		exportEncrypted = false;
		exportedKey = key.ToPuttyPrivateKey(exportEncrypted);
		console.log("The key " + secretkey5 + " has been saved to file " + secretname5 + ".ppk");
		success = key.SaveText(exportedKey,"privkey_putty_unencrypted.ppk");
		fs.renameSync('privkey_putty_unencrypted.ppk', secretname5 + '.ppk');
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "6" ){
		var secretkey6 = 0;
		if (fs.existsSync(secretkey6 + ".ppk")) {
			console.log("File already exists")
			process.exit()

		}
		secretkey6 = readline.question(`Please enter a secret key: \n`);
		secretname6 = readline.question(`Please enter a file name: \n`);
		console.log("The key " + secretkey6 + " has been saved to file " + secretname6 + ".ppk");
		key.Password = secretkey6;
		exportEncrypted = true;
		exportedKey = key.ToPuttyPrivateKey(exportEncrypted);
		success = key.SaveText(exportedKey,"privkey_putty_encrypted.ppk");
		fs.renameSync('privkey_putty_encrypted.ppk', secretname6 + '.ppk');
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "7" ){
		var secretkey7 = 0;
		secretname7 = readline.question(`Please enter a file name: \n`);
		if (fs.existsSync(secretkey7 + ".xml")) {
			console.log("File already exists")
			process.exit()

		}
		exportedKey = key.ToXml();
		success = key.SaveText(exportedKey,"privkey.xml");
		fs.renameSync('privkey.xml', secretname7 + '.xml');
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "8" ){
		var secretkey8 = 0;
		secretname8 = readline.question(`Please enter a file name: \n`);
		if (fs.existsSync(secretkey8 + ".pub")) {
			console.log("File already exists")
			process.exit()

		}
		exportedKey = key.ToRfc4716PublicKey();
		success = key.SaveText(exportedKey,"pubkey_rfc4716.pub");
		fs.renameSync('pubkey_rfc4716.pub', secretname8 + '.pub');
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "9" ){
		var secretkey9 = 0;
		secretname9 = readline.question(`Please enter a file name: \n`);
		if (fs.existsSync(secretkey9 + ".pub")) {
			console.log("File already exists")
			process.exit()

		}
		exportedKey = key.ToOpenSshPublicKey();
		success = key.SaveText(exportedKey,"pubkey_openSsh.pub");
		fs.renameSync('pubkey_openSsh.pub', secretname9 + '.pub');
		console.log('Key Saved to: ' + process.cwd());

    }else if (cmdArgument[0] == "10" || cmdArgument[0] == "quit"){
		console.log("Exiting Program..")
		console.log("Thank you for using JS Encrypter")
    }else{ 
        //default for if the argument isn't recognised, or if there is no argument
        console.log("It seems you ran an invalid command, please run [ node main.js help ] for a list of commands and how to use them.")
    };
};

function encrypt(text, password){
    // creates a cipher using the chosen algorithm and the password
    var cipher = crypto.createCipher(algorithm,password)
    // creates a crypted version of the text using the cipher
    var crypted = cipher.update(text,'utf8','hex')
    //ensures the crypted is returned in a hex format
    crypted += cipher.final('hex');
    return crypted;
};

function decrypt(text, password){
    //creates the decipher
    var decipher = crypto.createDecipher(algorithm,password)
    //actually does the deciphering
    var dec = decipher.update(text,'hex','utf8')
    //makes sure to output in the right format
    dec += decipher.final('utf8');
    return dec;
};

function readFile(fileName,state,pwd){
    //checks if the if file exists, and if it doesn't then it errors. If not, it does nothing
    fs.stat(fileName, function(err, stat) {
        if(err == null) {
            //do nothing
        } else if(err.code === 'ENOENT') {
            console.log("The file path you provided,", fileName, "cannot be found. Ensure that the path to your file is correct.");
            //exit the program
            process.exit(1);
        } else {
            console.log('Some other error: ', err.code);
        }
    });
    
    //takes the path to the file, the encoding, and some general info.
    //if it errors, then it returns the error. Otherwise, the contents of the file are put into the "txt" variable
    fs.readFile(fileName, 'utf8', function (err,data) {
        if (err) {
          return console.log(err);
        }
        text = data;

        //if the 'state' from the main menu is encrypt, then it encrypts. And vice versa
        if (state == "encrypt"){
            var cryptedText = encrypt(text,pwd)
            //console.log(cryptedText)
            updateFile(fileName,state,cryptedText)
        }else if (state == "decrypt"){
            var decryptedText = decrypt(text,pwd)
            //console.log(decryptedText)
            updateFile(fileName,state,decryptedText)
        }
      });
};

function updateFile(fileName, state, content){
    newPath = fileName.replace(/.[a-z]{3,}$/g,"")+"_"+state+"ed.txt";
    fs.writeFile(newPath, content, function(err){
        if (err) throw err;
        console.log('Saved to:', newPath);
    })
};

function passwordGen(length){
    characters = "abcdefghijklmnopqrstuv1234567890-+.,?!&*@#";
    generated = new Array();
    for(i=0; i < length; i++){
        x = Math.floor(Math.random() * (characters.length - 0) + 0); // generates a random number between 0 and the length of the character set. Then uses Math.floor to round
        generated.push(characters[x]);
    }
    return generated.toString().replace(/,/g,"");
};

menu();

