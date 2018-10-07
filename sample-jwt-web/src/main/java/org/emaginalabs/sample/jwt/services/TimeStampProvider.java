package org.emaginalabs.sample.jwt.services;

import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;

@Service
public class TimeStampProvider {

    public Date getCurrentDate() {
        return Calendar.getInstance().getTime();
    }

}
