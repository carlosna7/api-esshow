const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
require("dotenv").config()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
const port = 5050

const jwtKey = 'secret-security-key'

// Middleware
app.use(cors())
app.use(express.json())

mongoose.connect(process.env.MONGODB)

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    shows: [
        {
            artist: String,
            cache: String,
            image: String,
            date: String,
            estado: String,
            cidade: String,
        }
    ],
})

const Users = mongoose.model('Users', userSchema)

app.post('/verify-token', (req, res) => {
    const { token } = req.body
    try {
        const decoded = jwt.verify(token, jwtKey)
        res.json({ expired: false })
    } catch (error) {
        res.json({ expired: true })
    }
})

app.get('/user/:_id', async (req, res) => {
    try {
        const user = await Users.findById(req.params._id).select('-password')

        if (!user) {
            return res.status(401).json({ error: 'Email ou senha incorretos' });
        }

        res.json(user)

    } catch (error) {
        console.error(error)
        res.status(500).send('Internal Server Error')
    }
})

app.post('/user/register', async (req, res) => {
    try {
        const { name, email, password, shows } = req.body
        
        const userExist  = await Users.findOne({ email })

        if (userExist) {
            return res.status(401).json({ error: 'Email já esta sendo utilizado em outra conta!' })
        }

        const saltRounds = 10
        const hashPassword = await bcrypt.hash(password, saltRounds)
        
        const user = new Users({ 
            name, 
            email,
            password: hashPassword,
            shows
        })

        await user.save()
        res.json({ msg: 'Usuário cadastrado com sucesso!'})

    } catch (error) {
        console.error(error)
        res.status(500).send('Internal Server Error')
    }
})

app.post('/user/login', async (req, res) => {
    try {
        const { email, password } = req.body

        const user  = await Users.findOne({ email })

        if (!user) {
            return res.status(401).json({ error: 'Email ou senha incorretos' })
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Email ou senha incorretos' })
        }

        // passa o userID do mongoDB como token
        const token = jwt.sign({ userId: user._id }, jwtKey, { expiresIn: "1h" })

        res.json(token)

    } catch (error) {
        console.error(error)
        res.status(500).send('Internal Server Error')
    }
})

app.patch('/user/shows/:_id', async (req, res) => {
    try {
        const { shows } = req.body
        const user = await Users.findById(req.params._id)

        if (!user) {
            return res.status(401).json({ error: 'Usuário não encontrado' })
        }

        user.shows.push(shows)

        const updatedUser = await user.save()

        const showsData = await Users.findById(req.params._id).select('-password -email')
        res.json(showsData)
        
    } catch (error) {
        console.error(error)
        res.status(500).send('Internal Server Error')
    }
})

app.delete('/user/shows/:userId/:showId', async (req, res) => {
    try {
        const { userId, showId } = req.params
        const user = await Users.findById(userId)
        if(!user) {
            return res.status(404).send({ error: 'Usuário não encontrado'})
        }

        const show = user.shows.id(showId)
        if (!show) {
            return res.status(404).send({ error: 'Show não encontrado'})
        }

        user.shows.pull(showId)
        await user.save()
        
        res.json(show)

    } catch (error) {
        console.error(error)
        res.status(500).send('Internal Server Error')
    }
})

app.listen(port, () => {
    console.log(`App running on port ${port}`)
})