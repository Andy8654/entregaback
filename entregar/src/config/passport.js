import 'dotenv/config'
import local from 'passport-local' //Estrategia
import passport from 'passport' //Manejador de las estrategias
import GithubStrategy from 'passport-github2'
import jwt from 'passport-jwt'
import { createHash, validatePassword } from '../utils/bcrypt.js'
import { userModel } from '../models/users.models.js'


//Defino la estrategia a utilizar
const LocalStrategy = local.Strategy

const JWTStrategy = jwt.Strategy
const ExtractJWT = jwt.ExtractJwt //Extractor de los headers de la consulta

const initializePassport = () => {

    const cookieExtractor = req => {
        //{} no hay cookies != no exista mi cookie
        //Si existen cookies, consulte por mi cookie y sino asigno {}
        const token = req.cookies ? req.cookies.jwtCookie : {}
        return token
    }

    passport.use('jwt', new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]), //Consulto el token de las cookies
        secretOrKey: process.env.JWT_SECRET
    }, async (jwt_payload, done) => {
        try {
            return done(null, jwt_payload) //Retorno el contenido del token
        } catch (error) {
            return done(error)
        }
    }))

