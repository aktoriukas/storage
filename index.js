const fs = require('fs')
const read = require('read')
const crypto = require('crypto')
const bcrypt = require('bcrypt')

require('dotenv').config(({ path: `${__dirname}/.env`}))

// OPEN THE APP ===================================================


const runApp = async () => {

    let secret = ''
    let data = {}

    const rounds = 9921
    const saltRounds = 10
    const keySize = 32
    const algorithm = 'aes-256-cbc'
    let mistake = 0

    const makeSalt = () => {
        return crypto.createHash('sha1').update(secret).digest("hex")
    }
    

    // GET USER INPUT ===================================================

    const getUserInput = async (txt, hidden) => {

        return new Promise( (resolve, reject) => {

            if(!hidden){

                read({ prompt: txt, silent: hidden}, (er, answer) => {
                    if(er){ console.log(new Error(er)) }
                    resolve(answer)
                })        
            }else{
                read({ prompt: txt, silent: hidden, replace:'*'}, (er, answer) => {
                    if(er){ console.log(new Error(er)) }
                    resolve(answer)
                })    
            }

        })
    }
    
    // GET INITIAL PASSWORD ===========================================
    
    const getPassword = (hash) =>{
    
        read({ prompt: 'Password: ', silent: true, replace: '*' }, (er, password) => {

            if(er){ console.log(new Error(er)) }
            pass = password
            newBreaker()
               
            if(decryptPass(password, hash)){
                // CORRECT PASSWORD

                secret = password
                const fileData = decryptData(getDataFromFile())
                fileData ? data = fileData : data = {}
                displayHelp()
            }
            else{
                // INCORRECT PASSWORD

                console.log('incorrect')
                mistake++
                if(mistake > 2) {
                    printY('bye')
                    return false
                }
                getPassword()
            }
        })

    }

    // DATA MANIPULATIONS ===========================================

    // ENCRYPT -----------------------------------

    const encryptData = () => {
        try {
            let iv = crypto.randomBytes(16);
            let key = crypto.pbkdf2Sync(secret, makeSalt(), rounds, keySize, 'sha512');
            let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
            let encryptedData = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
            return iv.toString('base64') + ':' + encryptedData.toString('base64');
        }
        catch (err) {
            console.error(err)
            return 
        }
    }
    const encryptPass = (password) => {
        return bcrypt.hashSync(password, saltRounds, (err, hash) => {
            if(err){ console.log(new Error(err)) }
            return hash
        });    
    }


    // DECRYPT -----------------------------------

    const decryptPass = (password, hash) => {

        if(hash) return bcrypt.compareSync(password, hash)
    
        return bcrypt.compareSync(password, process.env.NR1);
    }

    const decryptData = (data) => {

        try {
            let textParts = data.split(':');
            let iv = Buffer.from(textParts.shift(), 'base64');
            let encryptedData = Buffer.from(textParts.join(':'), 'base64');
            let key = crypto.pbkdf2Sync(secret, makeSalt(), rounds, keySize, 'sha512');
            let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
            let decryptedData = decipher.update(encryptedData);
            decryptedData = Buffer.concat([decryptedData, decipher.final()]);
            return JSON.parse(decryptedData.toString());
        }
        catch (err) {
            console.log('There is no data to decrypt')
            newBreaker()
            return
        }
    }    
    
    // READ FILE

    const getDataFromFile = () => {

        return fs.readFileSync(`${__dirname}/myfile.txt`, 'utf8', (err,data) => {
            if (err) { 
                console.log(new Error(err))
                return 
            }
            return data

        });
    }

    // SHOW DATA

    const showData = () => {

        if(data){ console.table(data) }
        else{ printY('empty') }

        newBreaker()

        return getMenu()
    }

    // ADD DATA

    const addData = async (newPassword) => {

        const name = await getUserInput('Name:', false)

        if(!newPassword){
            newPassword = await getUserInput('Password:', false)
        }

        data[name] = newPassword
        const encryptedData = encryptData()
        saveDataToFile(encryptedData)

        newBreaker()

        return getMenu()
    }

    // EDIT DATA

    const editData = async () => {

        if(data){
            const index = await getUserInput('Index:', false)
            const value = await getUserInput('New value:', false)
            data[index] = value
            const encryptedData = encryptData()
            saveDataToFile(encryptedData)
    
            printY('Data been updated')
            newBreaker()
        }else{
            printY('No data to edit')
        }

        return getMenu()
    }

    // DELETE DATA

    const deleteData = async () => {

        const index = await getUserInput('Index:', false)
        const answer = await getUserInput(`You sure wanna delete ${index}?`, false)

        if(answer === 'yes' || answer === 'y'){
            delete data[index]
            const encryptedData = encryptData()
            saveDataToFile(encryptedData)
            printY(`${index} has been deleted`)
            newBreaker()
        }
        return getMenu()
    }

    // SAVE TO FILE ===========================================

    const generateRandomPassword = async () => {

        const randomWord = await getUserInput('Random word:', false)
        const lenght = await getUserInput('Lenght of Password:', false)

        const hashPass = bcrypt.hashSync(randomWord, saltRounds, (err, hash) => { return hash })

        const cutPass = hashPass.slice(0, lenght)
        newLine()
        console.log(`Your password: ${cutPass}`)
        newBreaker()

        const answer = await getUserInput('Save this password?', false)

        if(answer === 'yes' || answer === 'y'){

            return addData(cutPass)
        }
        getMenu()
    }

    // SAVE TO FILE ===========================================

    const saveDataToFile = (data) => {

        fs.writeFileSync(`${__dirname}/myfile.txt`, data)
        newLine()
        console.log('data been saved')
        return 
    }

    // HELP ================================================

    const displayHelp = () => {

        printY('$ -s', 'show pass')
        printY('$ -e', 'edit pass')
        printY('$ -d', 'delete pass')
        printY('$ -q', 'quit')
        printY('$ -a', 'add pass')
        printY('$ -r', 'random pass')
        newBreaker()
        getMenu()
    }

    // MENU ================================================

    const getMenu = () =>{
    
        read({ prompt: 'Menu:', silent: false }, (er, option) => {

            if(er){ console.log(new Error(er)) }

            switch(option){
                case '-h': // HELP
                    displayHelp()
                    break

                case '-s': // SHOW PASSWORDS
                    showData()
                    break

                case '-e': // EDIT PASSWORD
                    editData()
                    break

                case '-a': // ADD PASSWORD
                    addData()
                    break

                case '-r': // GENERATE PASSWORD
                    generateRandomPassword()
                    break

                case '-d': // DELETE PASSWORD
                    deleteData()
                    break

                case '-q': // QUIT
                    printY('bye')
                    return

                default:
                    getMenu()
                    break
            }
        })
    }
    const initialRun = async () => {

        if(process.env.NR1){

            getPassword()

        }else{
            newBreaker()
            console.log('First time login required password set-up.')
            const password = await getUserInput('Password:', true)
            const rePassword = await getUserInput('Re-Password:', true)
            if(password === rePassword){

                const hash = encryptPass(password)
                fs.writeFileSync(`${__dirname}/.env`, `NR1=${hash}`, (err) => {
                    if (err) { console.log( new Error(err) )}
                })
                console.log('Password been saved')
                newBreaker()
                getPassword(hash)  

            }else {
                newBreaker()
                console.log('Passwords are not matching')
            }
        }
        

    }
    initialRun()
}    

const newLine = () => { console.log('\n') }
const newBreaker = () => { printY('------------------------------') }
const printY = (txt, txt2 = '') => { console.log('\x1b[33m%s\x1b[0m', txt, txt2 )}
const printM = (txt, txt2 = '') => { console.log('\x1b[35m%s\x1b[0m', txt, txt2 )}


runApp();