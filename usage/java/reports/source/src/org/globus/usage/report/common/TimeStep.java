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
    int stepSize; /* Units of step Calendar.DATE, Calendar.MONTH */
    int stepMultiplier; /* Number of units per step 7 days, 2 months, etc */
    int stepNumber; /* Number of steps */
    int steps; /* Number of remaining steps */
    Calendar calendar;

    public TimeStep(String step, int stepNumber, String date)
    throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        int stepSize;

        if (step.equalsIgnoreCase("day")) {
            stepSize = Calendar.DATE;
        } else {
            stepSize = Calendar.MONTH;
        }

        init(dateFormat.parse(date), stepSize, stepNumber, 1);
    }

    public TimeStep(TimeStep ts) {
        init(ts.calendar.getTime(), ts.stepSize, ts.steps, ts.stepMultiplier);
    }

    public TimeStep(Date startDate, int stepSize, int steps) {
        init(startDate, stepSize, steps, 1);
    }

    public TimeStep(Date startDate, int stepSize, int steps, int stepMultiplier) {
        init(startDate, stepSize, steps, stepMultiplier);
    }

    private void init(Date startDate, int stepSize, int steps,
            int stepMultiplier) {
        this.stepMultiplier = stepMultiplier;
        this.steps = steps;
        this.stepNumber = steps;
        this.stepSize = stepSize;
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

    public int getStepMultiplier() {
        return stepMultiplier;
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
            calendar.add(stepSize, stepMultiplier);
            steps = steps - 1;
            return calendar.getTime();
        } else {
            return null;
        }
    }
}
