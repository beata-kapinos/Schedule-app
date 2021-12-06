const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const { body, validationResult } = require('express-validator')
const {Pool} = require('pg')
const app = express()
const port = 3000

const authTokens = {}

app.use(express.json())
app.set('view engine', 'pug')
app.use(express.urlencoded())
app.use(cookieParser())

app.use((req, res, next) => {
  const authenticatedUser = authTokens[req.cookies['AuthToken']]
  const protectedRoutes = ['/schedules']

  res.locals.authenticatedUser = authenticatedUser

  if (protectedRoutes.includes(req.path) && !authenticatedUser) {
    res.redirect('/login')
  } else {
    next()
  }
})

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'Mr. Coffee2',
  password: 'password',
  port: 5432
})

app.get (
    '/login', async (req, res) => {
        res.render('login.pug', { data: {} })
      }
  )

app.post(
    '/login',
    async function (req,res) {
      const crypto = require('crypto');
      const hashedPassword = crypto.createHash('md5').update(req.body.password).digest('hex')
      const client = await pool.connect()
      const result = await client.query('SELECT * FROM public."Users" WHERE email_address = $1 AND password = $2', [req.body.email_address, hashedPassword])

      if (result.rows.length === 1) {
        const authToken = crypto.randomBytes(30).toString('hex');

        authTokens[authToken] = result.rows[0]

        res.cookie('AuthToken', authToken)

        res.redirect('/schedules')
      } else {
          res.render('login.pug', {data: req.body, errorMessage:'Email address or password is incorrect.'})
      }
      client.release()
    }
)

app.get (
    '/schedules', async (req, res) => {
      const client = await pool.connect()
      const result = await client.query('SELECT * FROM public."Schedules"')
      
      res.render('schedules.pug', {schedules: result.rows})
      console.log(result.rows)
      client.release()
      }
  )

app.get (
    '/signup', async (req, res) => {
        res.render('signup.pug', { data: {} })
      }
  )

app.post (
    '/signup',
    body('lastname').not().isEmpty().withMessage('Last name is required').trim().escape(),
    body('name').not().isEmpty().withMessage('Name is required').trim().escape(),
    body('email_address').isEmail().withMessage('Invalid email address'),
    body('email_address').custom(async (value, { req }) => {
      const client = await pool.connect()
      const result = await client.query('SELECT * FROM public."Users" WHERE email_address = $1', [req.body.email_address])

      if (result.rows.length) {
        throw new Error('E-mail already in use')
      } else {
        return true;
      }

      client.release()
    }),
    body('password').isLength({ min: 5 }).withMessage('The password must be at least 5 characters long'),
    body('repeat_password').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }

      // Indicates the success of this synchronous custom validator
      return true;
    }),
    async (req, res) => {
      const errors = validationResult(req);
      console.log(errors.array())
      if (!errors.isEmpty()) {
        res.render('signup.pug', { errors: errors.array(), data: req.body})
      } else {
        const crypto = require('crypto');
        const hashedPassword = crypto.createHash('md5').update(req.body.password).digest('hex');
        const client = await pool.connect()
        await client.query('INSERT INTO public."Users" (lastname, name, email_address, password) VALUES ($1, $2, $3, $4)',[req.body.lastname, req.body.name, req.body.email_address, hashedPassword])
        res.redirect('/login')
        client.release()
      }
    }
)

app.get (
  '/logout', async (req, res) => {
    const authToken = req.cookies['AuthToken']

    if (authToken) {
      delete authTokens[authToken]
      res.clearCookie('AuthToken')
    }

    res.redirect('/login')
  }
)

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
  })