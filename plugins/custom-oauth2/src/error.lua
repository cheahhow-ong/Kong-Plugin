local _M = {}

-- function to hold all errors that will be called in access.lua
local function get_mapped_error(custom_error_code_and_language)
    local eng = "en-TH"
    local thai = "th-TH"
    local error_msg_mappings = {}

    kong.log("custom_error_code_and_language: ", custom_error_code_and_language)

    -- errors in english
    error_msg_mappings["80004" .. eng] = {
        ["code"] = "80004",
        ["title"] = "Auth header error",
        ["description"] = "Authorization header is missing, incorrect or invalid authorization token.",
        ["message"] = "Please try again."
    }

    error_msg_mappings["80010" .. eng] = {
        ["code"] = "80010",
        ["title"] = "Invalid Token or Token Expired",
        ["description"] = "Access is denied because pre-login scoped access token expired or is invalid.",
        ["message"] = "Please put a new Token code"
    }
   
    error_msg_mappings["80011" .. eng] = {
        ["code"] = "80011",
        ["title"] = "Token Expired.",
        ["description"] = "Access is denied because access token expired.",
        ["message"] = "Please put a new Token code"
    }

    error_msg_mappings["80012" .. eng] = {
        ["code"] = "80012",
        ["title"] = "Token Expired.",
        ["description"] = "Access is denied because refresh token expired.",
        ["message"] = "Please refresh and put a new Token code"
    }
    
    error_msg_mappings["80013" .. eng] = {
        ["code"] = "80013",
        ["title"] = "Invalid Grant Type",
        ["description"] = "Access is denied because grant type is invalid.",
        ["message"] = "Please try again."
    }

    error_msg_mappings["80014" .. eng] = {
        ["code"] = "80014",
        ["title"] = "<Data> did not match our records",
        ["description"] = "No route matched with route specified in request.",
        ["message"] = "Please try again."
    }
    
    error_msg_mappings["80015" .. eng] = {
        ["code"] = "80015",
        ["title"] = "Session Expired",
        ["description"] = "Access is denied because access token is invalid. User is kicked out of session.",
        ["message"] = "<Activity>attempts exceeded. Your account has been locked. Please contact<x>"
    }

    error_msg_mappings["80016" .. eng] = {
        ["code"] = "80016",
        ["title"] = "Session Expired",
        ["description"] = "Access is denied because refresh token is invalid. User is kicked out of session.",
        ["message"] = "<Activity>attempts exceeded. Your account has been locked. Please contact<x>"
    }
       
    -- errors in thai
    error_msg_mappings["80004" .. thai] = {
        ["code"] = "80004",
        ["title"] = "ทำรายการเกินเวลาที่กำหนด",
        ["description"] = "Authorization header is missing, incorrect or invalid authorization token.",
        ["message"] = "กรุณาลองใหม่อีกครั้ง"
    }

    error_msg_mappings["80010" .. thai] = {
        ["code"] = "80010",
        ["title"] = "โทเค็นไม่ถูกต้อง/โทเค็นหมดอายุ",
        ["description"] = "Access is denied because pre-login scoped access token expired or is invalid.",
        ["message"] = "กรุณากรอกรหัสโทเค็นใหม่"
    }
   
    error_msg_mappings["80011" .. thai] = {
        ["code"] = "80011",
        ["title"] = "โทเค็นหมดอายุ",
        ["description"] = "Access is denied because access token expired.",
        ["message"] = "กรุณากรอกรหัสโทเค็นใหม่"
    }

    error_msg_mappings["80012" .. thai] = {
        ["code"] = "80012",
        ["title"] = "โทเค็นหมดอายุ",
        ["description"] = "Access is denied because refresh token expired.",
        ["message"] = "กรุณารีเฟรชโทเค็นและกรอกรหัสโทเค็นใหม่"
    }
    
    error_msg_mappings["80013" .. thai] = {
        ["code"] = "80013",
        ["title"] = "ประเภทการให้สิทธิ์ไม่ถูกต้อง",
        ["description"] = "Access is denied because grant type is invalid.",
        ["message"] = "กรุณาลองใหม่อีกครั้ง"
    }

    error_msg_mappings["80014" .. thai] = {
        ["code"] = "80014",
        ["title"] = "ไม่พบ<ข้อมูล>",
        ["description"] = "No route matched with route specified in request.",
        ["message"] = "กรุณาลองใหม่อีกครั้ง"
    }
    
    error_msg_mappings["80015" .. thai] = {
        ["code"] = "80015",
        ["title"] = "ออกจากระบบ",
        ["description"] = "Access is denied because access token is invalid. User is kicked out of session.",
        ["message"] = "<Activity>attempts exceeded. Your account has been locked. Please contact<x>"
    }

    error_msg_mappings["80016" .. thai] = {
        ["code"] = "80016",
        ["title"] = "ออกจากระบบ",
        ["description"] = "Access is denied because refresh token is invalid. User is kicked out of session.",
        ["message"] = "<Activity>attempts exceeded. Your account has been locked. Please contact<x>"
    }

    return error_msg_mappings[custom_error_code_and_language]
end

local function get_generic_error(language, description)
    local eng = "en-TH"
    local thai = "th-TH"
    local error_msg_mappings = {}

    kong.log("language: ", language)
    kong.log("description: ", description)
    
    -- in english
    error_msg_mappings[eng] = {
        ["code"] = "80000",
        ["title"] = "Unable to proceed",
        ["description"] = description,
        ["message"] = "Please try again."
    }

    kong.log("error_msg_mappings[eng]")
    kong.log.inspect(error_msg_mappings[eng])

    -- in thai
    error_msg_mappings[thai] = {
        ["code"] = "80000",
        ["title"] = "ไม่สามารถทำรายการได้",
        ["description"] = description,
        ["message"] = "กรุณาลองใหม่อีกครั้ง"
    }

    kong.log("error_msg_mappings[thai]")
    kong.log.inspect(error_msg_mappings[thai])

    kong.log("error_msg_mappings[language]")
    kong.log.inspect(error_msg_mappings[language])

    return error_msg_mappings[language]
end

function _M.execute_get_mapped_error(custom_error_code_and_language)
    return get_mapped_error(custom_error_code_and_language)
end

function _M.execute_get_generic_error(language, description)
    return get_generic_error(language, description)
end

return _M