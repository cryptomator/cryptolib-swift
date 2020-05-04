Pod::Spec.new do |s|
  s.name             = 'CryptomatorCryptoLib'
  s.version          = '0.1.0'
  s.summary          = 'CryptomatorCryptoLib is an iOS crypto library to access Cryptomator vaults.'


  s.homepage         = 'https://github.com/cryptomator/cryptolib-swift'
  s.license          = { :type => 'AGPLv3', :file => 'LICENSE.txt' }
  s.author           = { 'Philipp Schmid' => 'philipp.schmid@skymatic.de',
                         'Sebastian Stenzel' => 'sebastian.stenzel@skymatic.de' }
  s.source           = { :git => 'https://github.com/cryptomator/cryptolib-swift.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/Cryptomator'

  s.public_header_files = 'CryptoLib/CryptoLib.h'
  s.ios.deployment_target = '8.0'
  s.swift_version = '5.0'
    
  s.source_files = 'CryptoLib/**/*{swift,h,m}'
  
  s.dependency 'CryptoSwift', '~> 1.3'
  s.dependency 'SwiftBase32', '~> 0.8'
end
