const { Usuario } = require('../models/');
const bcrypt = require('bcryptjs')
const srvToken = require('../services/token')


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

    add : async (req, res, next) => {
        try {
            const EncriptedPassword = bcrypt.hashSync(req.body.password)
            const re = await Usuario.create({rol: req.body.rol, nombre: req.body.nombre, password: EncriptedPassword, email: req.body.email, estado: req.body.estado});
            res.status(200).json(re);
            
        } catch (error) {
            res.status(500).send({ message: 'Ocurrió un error' });
            next(error)
        }
    },

    // rol (perfil) nombre password email estado.
    
    update : async (req, res, next) => {
        try {

            // Buscar usuario por email
            const user = await Usuario.findOne( {where:{ id : req.body.id }} );
            
            // validando contraseña
            const validPassword = bcrypt.compareSync(req.body.password, user.password)

            // Busca contraseña encriptada
            const EncriptedPassword = req.body.newpassword ? bcrypt.hashSync(req.body.newpassword) :bcrypt.hashSync(user.password)

            if(validPassword) {
                const re = await Usuario.update({nombre: req.body.nombre, email: req.body.email, password: EncriptedPassword}, {where: {id: req.body.id}});
                res.status(200).json(re);
            } else {
                res.status(401).send({ auth: false, tokenReturn: null, reason: "Contraseña invalida"});
            }        
        } catch (error) {
            res.status(500).json({ 'error' : 'Oops paso algo' })
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
                    
                    const token = await srvToken.encode(user.id, user.rol)
                    
                    res.status(200).send({
                        auth : true,
                        tokenReturn : token,
                        user : user
                    })

                }  else {
                    res.status(401).send({ auth: false, tokenReturn: null, reason: "Contraseña invalida"})
                }
    
            } else {
                res.status(404).send({ auth: false, tokenReturn: null, reason: "Usuario invalido"})
            }
    
        } catch (error) {
            res.status(500).json({ 'error' : 'Oops paso algo' })
            next(error)
        }
    
    
    },

    activate : async (req, res, next) => {
        try {
            const re = await Usuario.update({estado: 1}, {where: {id: req.body.id}})
            res.status(200).json(re)
            
        } catch (error) {
            res.status(500).json({ 'error' : 'Oops paso algo' })
            next(error)
        }

    },

    deactivate : async (req, res, next) => {
        try {
            const re = await Usuario.update({estado: 0}, {where: {id: req.body.id}})
            res.status(200).json(re)
            
        } catch (error) {
            res.status(500).json({ 'error' : 'Oops paso algo' })
            next(error)
        }
    },
}
    