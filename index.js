const serverless = require('serverless-http')
const express = require('express')
const firebase = require('firebase-admin')
const bodyParser = require('body-parser')
const fetch = require('node-fetch')

const {OAuth2Client} = require('google-auth-library');

const BASE_URL = 'https://9stbui4sud.execute-api.eu-central-1.amazonaws.com/prod'
const GOOGLE_CLIENT_ID = '485917417746-p6oifi42ajdc9v8q09e5543epso112ou.apps.googleusercontent.com'

const verifyGoogleToken = token => new Promise((resolve, reject) => {
  const client = new OAuth2Client(GOOGLE_CLIENT_ID);
  client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
  }).then(ticket => {
    const payload = ticket.getPayload();
    const userid = payload['sub'];

    return resolve(payload)
  }).catch(reject)
})

const serviceAccount = require('./firebase-service-key.json')
const app = express()

const crypto = require('crypto')
const getSha256 = str => crypto.createHmac('sha256', 'this is top secret')
  .update(str).digest('hex')
const md5 = str => crypto.createHash('md5').update(str).digest('hex')
const getSessionToken = (userId, skillId) => getSha256(userId + skillId)

const apiRoutes = express.Router()
const authRoutes = express.Router()

const getAuthSession = (sessionId) => new Promise((resolve, reject) => {
  const db = firebase.firestore()
  const session = db.collection('sessions').doc(sessionId)
  session.get()
    .then(doc => {
      if (!doc.exists) {
        return resolve(false)
      } else {
        return resolve(doc.data())
      }
    })
    .catch(error => {
      console.error(error)
      return reject(`cant get auth session: ${error.toString()}`)
    })
})

const isAuthenticatedSession = session => {
  if (!session || !session.providers) return false
  for (let provider in session.providers) {
    if (session.providers[provider].isAuthenticated) {
      return session.providers[provider]
    }
  }
  return false
}

const updateAuthSession = (sessionId, updateData) => new Promise((resolve, reject) => {
  const db = firebase.firestore()
  db.collection('sessions').doc(sessionId).update(updateData).then(resolve).catch(reject)
})

const createProviderAuthData = (provider, updateData) => ({
  providers: {
    [provider]: updateData
  }
})

const updateGoogleAuthSession = (sessionId, updateData) =>
  updateAuthSession(sessionId, createProviderAuthData('google', updateData))

const updateFacebookAuthSession = (sessionId, updateData) =>
  updateAuthSession(sessionId, createProviderAuthData('facebook', updateData))

const updateVKAuthSession = (sessionId, updateData) =>
  updateAuthSession(sessionId, createProviderAuthData('vk', updateData))

const createAuthSession = (userId, skillId) => new Promise((resolve, reject) => {
  const db = firebase.firestore()
  const sessionId = getSessionToken(userId, skillId)
  return getAuthSession(sessionId)
    .then(session => {
      // if there's already session, lets return it
      if (session) return resolve(session)
      // if no session, let's create it
      const defaultAuthState = {
        isAuthenticated: false,
        data: {}
      }
      const newSession = db.collection('sessions').doc(sessionId).set({
        userId: userId,
        skillId: skillId,
        timestamp: {
          created: new Date().toString()
        },
        providers: {
          google: defaultAuthState,
          facebook: defaultAuthState,
          vk: defaultAuthState
        }
      }).then(doc => {
        console.log(doc)
        return resolve(newSession)
      })
    })
    .catch(reject)
})

authRoutes.get('', (req, res) => {
  const userId = req.query.user_id
  const skillId = req.query.skill_id
  if (!userId) {
    return res.json({
      error: 1,
      msg: `Missing {user_id}. Please, provide it`
    })
  }
  if (!skillId) {
    return res.json({
      error: 1,
      msg: `Missing {skill_id}. Please, provide it.`
    })
  }

  const sessionToken = getSessionToken(userId, skillId)
  createAuthSession(userId, skillId)
    .then(session => {
      console.log(session)
      return res.json({
        msg: 'OK! Now send this link to the user.',
        userUrl: `${BASE_URL}/signin?token=${sessionToken}`,
        serverUrl: `${BASE_URL}/callback/${sessionToken}`,
        token: sessionToken
      })
    })
    .catch(error => {
      console.error(error)
      res.json({
        error: 1,
        msg: error.toString(),
      })
    })
})

// VK authentication strategy
authRoutes.get('/vk/:sessionId', (req, res) => {
  const APP_ID = '5023767'
  const APP_SECRET = '6mZAz0f8JfYiZqEzZ9Y'
  const sessionId = req.params.sessionId
  if (!sessionId) return res.json({
    error: 1,
    provider: 'vk',
    msg: '/vk/{sessionId} is not defined'
  })
  const {
    uid,
    first_name,
    last_name,
    photo,
    hash
  } = req.query
  // Check if auth is from valid source
  if (hash !== md5(APP_ID + uid + APP_SECRET)) {
    return res.json({
      error: 1,
      msg: `Invalid {hash: ${hash}}. Authentication failed`
    })
  }

  // Authentication complete, update user data.
  updateVKAuthSession(sessionId, {
    uid, first_name, last_name, photo, hash
  }).then(r => {
    res.json({
      isAuthenticated: true,
      msg: 'Authentication via VK successfully completed'
    })
  }).catch(err => res.json({
    error: 1,
    msg: 'Unexpected error while auth via VK'
  }))
})

// Facebook authentication strategy
const composeFbResponse = data => Object.assign({}, {provider: 'fb'}, data)
const composeFbError = data => Object.assign(composeFbResponse(data), {error: 1}, data)
authRoutes.get('/fb/:sessionId', (req, res) => {
  const { sessionId } = req.params
  if (!sessionId) return res.json(composeFbError({msg: '/fb/{sessionId} is not defined'}))

  const accessToken = req.query.token
  if (!accessToken) return res.json(
    composeFbError({msg: '/fb/sessionId?token={accessToken} is not defined'})
  )

  getAuthSession(sessionId).then(session => {
    if (!session) return res.json({
      error: 1,
      msg: `Session ${sessionId} does not exist.`
    })

    fetch(`https://graph.facebook.com/me?access_token=${accessToken}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) return res.json(
          composeFbError({msg: 'Seems token is not valid (graph.facebook.com)'})
        )

        updateFacebookAuthSession(sessionId, {
          name: data.name,
          id: data.id
        }).then(res => {
          return res.json(
            composeFbResponse({
              isAuthenticated: true,
              msg: 'OK. Authenticated via Facebook'
            })
          )
        })
      })
      .catch(error => res.json(composeFbError({msg: 'Unexpected error while token verification'})))
  })
})

// Google authentication strategy
authRoutes.get('/google/:sessionid', (req, res) => {
  const { token } = req.query
  const sessionId = req.params.sessionid
  getAuthSession(sessionId).then(session => {
    if (!session) return res.json({
      error: 1,
      msg: `Session ${sessionId} does not exist.`
    })

    verifyGoogleToken(token)
      .then(data => {
        const {
          email,
          picture,
          given_name,
          family_name
        } = data
        updateGoogleAuthSession(sessionId, {
          isAuthenticated: true,
          data: data
        }).then(() => res.json({
          msg: 'Success! Authenticated with Google.'
        }))
      })
      .catch(error => res.json({
        error: 1,
        msg: `User's Google token is invalid`
      }))
  })
})

authRoutes.get('/callback', (req, res) => {
  const { token } = req.query
  if (!token) return res.json({
    error: 1,
    msg: 'Missing {token}. Please provide it.'
  })
})

app.use(express.static(__dirname))
app.use(bodyParser.json())
app.use('/auth', authRoutes)

app.get('/signin', function (req, res) {
  const db = firebase.firestore()
  res.sendFile(__dirname + '/index.html')
})

const onSuccessfullAuthentication = (sessionId) => new Promise(resolve => {
  const db = firebase.firestore()
  const doc = db.collection('sessions').doc(sessionId)
  const observer = doc.onSnapshot(sessionSnapshot => {
    const session = sessionSnapshot.data()
    console.log('trying', isAuthenticatedSession(session))
    if (isAuthenticatedSession(session)) {
      console.log('i am here now')
      return resolve(session)
    }
  }, err => console.error(err))
})


const formatUserSession = session => {
  const googleSession = session.providers.google.data
  const fbSession = session.providers.facebook.data
  const vkSession = session.providers.vk.data

  const reply = {
    given_name: googleSession.given_name || vkSession.first_name,
    family_name: googleSession.family_name || vkSession.last_name,
    email: googleSession.email || null,
    photo: googleSession.picture || vkSession.photo || null,
    user_id: session.userId,
    skill_id: session.skillId
  }
  return reply
}


const SUCCESS_AUTH_MSG = 'User has been successfully authenticated.'
app.get('/callback/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId
  const db = firebase.firestore()
  if (!sessionId) return res.json({error: 1, msg: `Missed /callback/{sessionid}`})
  getAuthSession(sessionId).then(session => {
    if (!session) return res.json({error: 1, msg: `Session {${sessionId}} does not exist`})
    console.log(session)

    if (isAuthenticatedSession(session)) {
      return res.json({
        isAuthenticated: true,
        msg: SUCCESS_AUTH_MSG,
        data: Object.assign({}, formatUserSession(session), {
          token: sessionId
        })
      })
    }

    console.log(`Not authenticated yet.`)
    // Not authenticated yet.
    // Set up realtime observer to check out the moment when user authenticated.
    onSuccessfullAuthentication(sessionId)
      .then(session => {
        console.log('now authenticated')
        return res.json({
          isAuthenticated: true,
          msg: SUCCESS_AUTH_MSG,
          data: Object.assign({}, formatUserSession(session), {
            token: sessionId
          })
        })
      })
      .catch(() => res.json({
        isAuthenticated: false,
        error: 1,
        msg: 'Authentication failed'
      }))
  })
})
module.exports.handler = (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false
  if(firebase.apps.length == 0) {
     firebase.initializeApp({
        credential: firebase.credential.cert(serviceAccount),
        databaseURL: "https://yandex-alice-auth.firebaseio.com"
      })
   }
  return serverless(app)(event, context, callback)
}