exports.handler = async (event) => {
    // 自动确认用户
    event.response.autoConfirmUser = true;
    
    // 如果用户注册时提供了邮箱，自动验证邮箱
    if (event.request.userAttributes.hasOwnProperty('email')) {
        event.response.autoVerifyEmail = true;
    }
    
    // 如果用户注册时提供了手机号，自动验证手机号
    if (event.request.userAttributes.hasOwnProperty('phone_number')) {
        event.response.autoVerifyPhone = true;
    }
    
    return event;
};
