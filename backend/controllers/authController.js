import bcrypt from "bcryptjs";
import jwt from 'jsonwebtoken';
import userModel from "../models/usermodel.js";
import transporter from "../config/nodemailer.js";
  

export const register = async (req,res) => {
    const {name, email,password} = req.body;

    if(!name || !email ||!password){
        return res.json({success: false, message: 'Missing details'});
    }

    try{

        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({success: false, message: "User already exist"});
        }

        const hashedPassword =  await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        
        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV  === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to My Project',
            text: `Welcome to My Project your account has been created with email id: ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});

    }catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async (req,res)=> {
    const {email, password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email & Password are required'})
    }
    try{
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'Invalid email'})
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch){
            return res.json({success: false, message: 'Invalid Password'})
        }
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        
        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV  === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        return res.json({success: true});

    } catch(error){
        return res.json({success: false, message: error.message})
    }
}
export const logout = async (req, res) => {
    try{
        res.clearCookie('token',{
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV  === 'production' ? 
            'none' : 'strict',
        })

        return res.json({success: true, message:'logged Out'})
    }catch(error){
        return res.json({success: false, message: message.error});
    }

}

//Send verification email to user   
export const sendVerifyOtp = async (req, res) => {
    try{

        const userId = req.user.id;  
        
        const user = await userModel.findById(userId);
         
        if(user.isAccountVerified){
            return res.json({success: false, message: 'Account already verified'});
        }
            const otp = String(Math.floor( 100000 + Math.random() * 900000));
            
            user.verifyotp = otp;
            user.verifyotpExpireAt = Date.now() + 10 * 60 * 1000; //10 minutes 
            await user.save();
            
            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: user.email,
                subject: 'Account Verification OTP',
                text: `Your account verification OTP is ${otp}. It is valid for 10 minutes.`
            }
             await transporter.sendMail(mailOptions);

            return res.json({success: true, message: 'OTP sent to your email'});

    }  catch(error){
            return res.json({success: false, message: error.message});        
    }

}

export const verifyEmail = async (req, res) => {
    const {otp} = req.body;
    const userId = req.user.id;
    
    if(!userId || !otp){
        return res.json({success: false, message: 'Missing required fields'});
    }
    try {
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({success: false, message: 'User not found'});
        }
        if(user.verifyotp === '' || user.verifyotp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyotpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP expired'});
        }
        user.isAccountVerified = true;
        user.verifyotp = '';
        user.verifyotpExpireAt = 0;
        
        await user.save();
        return res.json({success: true, message: 'Account verified successfully'});
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    } 
}
export const isAuthenticated = async (req, res) => {
    try{
        return res.json({success: true});

    }catch(error){
        res.json({success: false, message: error.message});
    }

}

//send password reset OTP

export const sendResetOtp = async (req, res) => {
        const {email} = req.body;

        if(!email){
            return res.json({success: false, message: 'Email is required'});
        }
        try {

            const user = await userModel.findOne({email});

            if(!user){
                return res.json({success: false, message: 'User not found'});
            }
            const otp = String(Math.floor( 100000 + Math.random() * 900000));
            
            user.resetOtp = otp;
            user.resetOtpExpireAt = Date.now() + 5 * 60 * 1000; //5 minutes 
            await user.save();
            
            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: user.email,
                subject: 'Password Reset OTP',
                text: `Your password reset OTP is ${otp}. It is valid for 5  minutes.`
            }
             await transporter.sendMail(mailOptions);

            return res.json({success: true, message: 'OTP sent to your email'});

        } catch (error) {
            return res.json({success: false, message: error.message});
        }
}

//reset User Password
export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: 'Missing required fields'});

    }
    try {
         const user = await userModel.findOne({email});
         if(!user){
            return res.json({success: false, message: 'User not found'});

         }
         if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
         }
         if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP expired'});
         }
         const hashedPassword = await bcrypt.hash(newPassword, 10);
         user.password = hashedPassword;
         user.resetOtp = '';
         user.resetOtpExpireAt = 0;

         await user.save();

        return res.json({success: true, message: 'Password reset successfully'});
        
    } catch (error) {
       return res.json({success: false, message: error.message});
    }

}