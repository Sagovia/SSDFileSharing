const createFileValidationSchema = {
    password: {
        optional: {
            options: { nullable: true }, // Allows password to be missing (Files don't need passwords always)
        },
        notEmpty: {
            errorMessage: "Password cannot be empty"
        },
        isString: {
            errorMessage: "Password must be a string"
        }
    },
    isPrivate: {
        isBoolean: {
            errorMessage: "isPrivate must be a boolean"
        },
        notEmpty: {
            errorMessage: "isPrivate must be set"
        }
    }
}

module.exports = createFileValidationSchema;