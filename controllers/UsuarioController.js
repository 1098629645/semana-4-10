const { Usuario } = require('../models/');
const bcrypt = require('bcryptjs')
const servToken = require('../services/token')


module.exports = {

    list : async (req, res, next) => {
        try {
            const re = await Usuario.findAll();
            res.status(200).json(re)
            
        } catch (error) {
            res.status(500).send({ message: 'Ocurrió un error' });
            next(error)
        }
        
    },

    register : async (req, res, next) => {
        try {
            //const re = await Usuario.create();
            
            res.status(500).send('pendiente por hacer reto personal')
            
        } catch (error) {
            res.status(500).send({ message: 'Ocurrió un error' });
            next(error)
        }
    },

    login : async (req, res, next) => {

        try {
            
            const user = await Usuario.findOne( {where:{ email : req.body.email }} )
            
            if(user){
                
                const contrasenhaValida = bcrypt.compareSync(req.body.password, user.password)
                if (contrasenhaValida)
                {
                    const token = servToken.encode(user.id, user.rol)

                    res.status(200).send({
                        auth : true,
                        tokenReturn : token,
                        user : user
                    })

                }  else {
                    res.status(401).send({ auth: false, tokenReturn: null, reason: "Contraseña invalida"})
                }
    
            } else {
                res.status(404).json({ 'error' : 'Usuario invalido' })
            }
    
        } catch (error) {
            res.status(500).json({ 'error' : 'Oops paso algo' })
            next(error)
        }
    
    
    }

}
    