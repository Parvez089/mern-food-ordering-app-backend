import { Request, Response,NextFunction } from "express"
import {body, validationResult} from "express-validator"

const handleValidation = async(req: Request, res: Response, next: NextFunction)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()})
    }
}

export const validateMyUserRequest = [
    body("name").isString().notEmpty().withMessage("Name must be a string"),
    body("addressLine1")
    .isString()
    .notEmpty()
    .withMessage("AddressLine must be a string"),

    body("city").isString().notEmpty().withMessage("City must be a string"),
    body("country").isString().notEmpty().withMessage("Country must be a string")
]