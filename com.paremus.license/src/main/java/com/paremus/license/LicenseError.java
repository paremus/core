/*-
 * #%L
 * com.paremus.license
 * %%
 * Copyright (C) 2016 - 2019 Paremus Ltd
 * %%
 * Licensed under the Fair Source License, Version 0.9 (the "License");
 * 
 * See the NOTICE.txt file distributed with this work for additional 
 * information regarding copyright ownership. You may not use this file 
 * except in compliance with the License. For usage restrictions see the 
 * LICENSE.txt file distributed with this work
 * #L%
 */
/*
 * Copyright 2006-2010 Paremus Limited. All rights reserved.
 * PAREMUS PROPRIETARY/CONFIDENTIAL. Use is subject to com.paremus.license terms.
 */

package com.paremus.license;

public class LicenseError extends Exception {
    private static final long serialVersionUID = 1L;

    public LicenseError(String m) {
        super(m);
    }

    public LicenseError(String m, Throwable e) {
        super(m, e);
    }
}
