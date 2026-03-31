package com.back.global.exception;

import com.back.global.rsData.RsData;

public class ServiceException extends RuntimeException {
    private String msg;
    private String resultCode;

    public ServiceException(String resultCode, String msg) {
        super(msg);
        this.msg = msg;
        this.resultCode = resultCode;
    }

    public RsData<Void> getRsDate() {
        return new RsData<>(
                msg,
                resultCode
        );
    }
}
