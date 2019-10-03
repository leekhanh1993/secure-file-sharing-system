const childprocess = require("child_process")
const bodyParser = require("body-parser")
const express = require("express");
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/******Receiver*****/
//decrypt encrypted key from sender
app.post("/decrypt-encrypted-key", (req, res) => {
    console.log(req.body.prvKeyContent)
    //create temporary private key
    var pathTmpPrvKEy = createTmpFile(req.body.prvKeyContent)
    var pathEncryptedKey = "./receiver/encrypted-key.txt"
    childprocess.exec(`openssl rsautl -in ${pathEncryptedKey} -inkey ${pathTmpPrvKEy} -decrypt`,
        (err1, stdout1, stderr1) => {
            if (err1) {
                fs.unlinkSync(pathTmpPrvKEy)
                res.status(404).send(err1)
            } else {
                fs.unlinkSync(pathTmpPrvKEy)
                res.send(stdout1)
            }
        })
})
//get encrypted key
app.get("/get-encr-AES-Secret-Key", (req, res) => {
    var filePath = "./receiver/encrypted-key.txt"
    if (fs.existsSync(filePath)) {
        res.send("encrypted-key.txt")
    } else {
        res.status(404).send("nothing")
    }
})
//get hash from sender
app.get("/get-hash", (req, res) => {
    var filePath = "./receiver/uqHash.txt"
    if (fs.existsSync(filePath)) {
        res.send(fs.readFileSync(filePath))
    } else {
        res.status(404).send("nothing")
    }
})
//gen key pair and send public key to sender
app.get('/generate-keypair', (req, res) => {
    childprocess.exec("openssl genrsa 2048", (err1, prv, stderr) => {
        if (err1) {
            res.status(404).send(err1)
        } else {
            var tmpPrv = "./" + Math.random().toString(36).substring(7)
            fs.writeFileSync(tmpPrv, prv)
            childprocess.exec(`openssl rsa -in ${tmpPrv} -pubout`, (err2, pub, stderr) => {
                if (err2) {
                    fs.unlinkSync(tmpPrv)
                    res.status(404).send(err2)
                } else {
                    fs.writeFileSync("./sender/public-key.pem", pub)
                    fs.unlinkSync(tmpPrv)
                    res.send(prv)
                }
            })
        }
    })
})

//download file from IPFSBased repository
app.post("/down-file-from-IPFSbased-repository", (req, res) => {
    childprocess.exec(`ipfs get ${req.body.IPFShash}`,
        (err1, stdout1, stderr1) => {
            if (err1) {
                res.status(404).send(err1)
            } else {
                childprocess.exec(`mv ${req.body.IPFShash} ./receiver/`, (err2, stdout2, stderr2) => {
                    if (err2) {
                        res.status(404).send(err2)
                    } else {
                        res.send("ok")
                    }
                })
            }
        })
})

//check encrypted file download from IPFS
app.get("/check-encrypted-file-download-from-IPFS", (req, res) => {
    var hash = fs.readFileSync("./receiver/uqHash.txt")
    if (fs.existsSync(`./receiver/${hash}`)) {
        res.send(hash)
    } else {
        res.status(404).send("error")
    }
})

//decrypt encrypted file AES
app.post("/decrypt-encrypted-file-AES", (req, res) => {
    var password = req.body.password
    var hash = req.body.hash
    var tmpFile = createTmpFile(hash)
    childprocess.exec(`openssl enc -aes-256-cbc -d -in ./receiver/${hash} -pass pass:${password}`,
        (err1, stdout1, stderr1) => {
            if (err1) {
                console.log(err1)
                res.status(404).send(err1)
            } else {
                fs.unlinkSync(tmpFile)
                res.send(stdout1)
            }
        })
})

/*******Sender**********/
//get public key from receiver
app.get("/get-public-key", (req, res) => {
    var filePath = "./sender/public-key.pem"
    if (fs.existsSync(filePath)) {
        res.send(fs.readFileSync(filePath))
    } else {
        res.status(404).send("nothing")
    }
})
//Sender Ecnrypt file with AES
app.post(`/encrypt-file-AES-with-secret-key`, (req, res) => {
    var password = req.body.password
    var plainText = req.body.plainText
    //create temporary file
    var tmpFile = "./" + Math.random().toString(36).substring(7)
    fs.writeFileSync(tmpFile, plainText)
    childprocess.exec(`openssl enc -aes-256-cbc -in ${tmpFile} -out ./sender/ciphertext.txt -k ${password}`,
        (err1, stdout1, stderr1) => {
            if (err1) {
                res.status(404).send(err1)
            } else {
                //upload encrypted AES file to IPFS-based repository
                childprocess.exec(`ipfs add ./sender/ciphertext.txt`, (err2, stdout2, stderr2) => {
                    if (err2) {
                        res.status(404).send(err2)
                    } else {
                        var tmpStr = stdout2.split(" ");
                        childprocess.exec(`ipfs get ${tmpStr[1]}`, (err3, stdout3, stderr3) => {
                            if (err3) {
                                res.status(404).send(err3)
                            } else {
                                //send has receiver
                                fs.writeFileSync("./receiver/uqHash.txt", tmpStr[1])
                                //remove temporary file
                                fs.unlinkSync(tmpFile)
                                //response
                                res.send("ok")
                            }
                        })
                    }
                })
            }
        })
})

//Sender sends AES Secret Key with public key to receiver 
app.post(`/encrypt-AES-Secret-Key-With-PubKey`, (req, res) => {
    var ogKeyCt = req.body.originalKeyContent
    //create tmpFile
    var pathTmpFile = createTmpFile(ogKeyCt)
    var pathPubKey = "./sender/public-key.pem"
    //ecnrypt AES secret Key
    childprocess.exec(`openssl rsautl -in ${pathTmpFile} -out ./receiver/encrypted-key.txt -pubin -inkey ${pathPubKey} -encrypt`,
        (err1, stdout1, stderr1) => {
            if (err1) {
                res.status(404).send(err1)
            } else {
                //remove temporary file
                fs.unlinkSync(pathTmpFile)
                res.send("ok")
            }
        })
})


app.get("/test", (req, res) => {
    res.send("Openssl Work!!!")
})

function createTmpFile(contentFile) {
    //create temporary file
    var tmpFile = "./" + Math.random().toString(36).substring(7)
    fs.writeFileSync(tmpFile, contentFile)
    return tmpFile
}
app.listen(port, () => console.log(`App is listening on port ${port}`))