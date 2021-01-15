//
//  scrypt.h
//  scrypt
//
//  Created by Tobias Hagemann on 15.01.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for scrypt.
FOUNDATION_EXPORT double scryptVersionNumber;

//! Project version string for scrypt.
FOUNDATION_EXPORT const unsigned char scryptVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <scrypt/PublicHeader.h>
#if COCOAPODS
#import "crypto_scrypt.h"
#else
#import <scrypt/crypto_scrypt.h>
#endif


