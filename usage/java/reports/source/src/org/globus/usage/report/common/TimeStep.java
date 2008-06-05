/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.usage.report.common;

import java.util.Date;
import java.util.Calendar;
import java.text.ParseException;
import java.text.SimpleDateFormat;

public class TimeStep {
    int stepSize;

    int stepNumber;

    int steps;

    Calendar calendar;

    public TimeStep(String step, int stepNumber, String date)
            throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        steps = stepNumber;
        this.stepNumber = stepNumber;
        if (step.equalsIgnoreCase("day")) {
            stepSize = Calendar.DATE;
        } else {
            stepSize = Calendar.MONTH;
        }

        Date currentDate = dateFormat.parse(date);
        calendar = dateFormat.getCalendar();
    }

    public TimeStep(int stepNumber, String date) throws ParseException {
        new TimeStep("day", stepNumber, date);
    }

    public TimeStep(String date) throws ParseException {
        new TimeStep("day", 1, date);
    }

    public TimeStep(Date startDate, int stepSize, int steps) {
        this.steps = steps;
        this.stepNumber = steps;
        stepSize = stepSize;
        calendar = Calendar.getInstance();
        calendar.setTime(startDate);
    }

    public boolean next() {
        return (steps > 0);
    }

    public Date getTime() {
        return calendar.getTime();
    }

    public int getStepSize() {
        return stepSize;
    }

    public int getSteps() {
        return steps;
    }

    public String getFormattedTime() {
        if (stepSize == Calendar.MONTH) {
            SimpleDateFormat df = new SimpleDateFormat("MMM,''yy");
            String datestr = df.format(calendar.getTime());
            return datestr;
        }
        if (stepSize == Calendar.DATE) {
            if (calendar.get(Calendar.DAY_OF_MONTH) == 1
                    || calendar.get(Calendar.DAY_OF_MONTH) % 10 == 0
                    || steps == 1 || steps == stepNumber) {
                SimpleDateFormat df = new SimpleDateFormat("MMM d,''yy");
                String datestr = df.format(calendar.getTime());
                return datestr;
            }
        }
        return "";
    }

    public Date stepTime() {
        if (steps > 0) {
            calendar.add(stepSize, 1);
            steps = steps - 1;
            return calendar.getTime();
        } else {
            return null;
        }
    }
}
