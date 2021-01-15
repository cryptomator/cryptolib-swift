Pod::Spec.new do |s|
  s.name             = 'CryptomatorCryptoLib'
  s.version          = ENV['LIB_VERSION'] || '0.0.1-snapshot'
  s.summary          = 'CryptomatorCryptoLib is an iOS crypto library to access Cryptomator vaults.'

  s.homepage         = 'https://github.com/cryptomator/cryptolib-swift'
  s.license          = { :type => 'AGPLv3', :file => 'LICENSE.txt' }
  s.author           = { 'Philipp Schmid' => 'philipp.schmid@skymatic.de',
                         'Sebastian Stenzel' => 'sebastian.stenzel@skymatic.de',
                         'Tobias Hagemann' => 'tobias.hagemann@skymatic.de' }
  s.source           = { :git => 'https://github.com/cryptomator/cryptolib-swift.git', :tag => s.version.to_s }

  s.public_header_files = 'Sources/CryptomatorCryptoLib/CryptomatorCryptoLib.h'
  s.source_files = 'Sources/CryptomatorCryptoLib/**/*.{swift,h}'
  s.ios.deployment_target = '9.0'
  s.osx.deployment_target = '10.12'
  s.swift_version = '5.1'

  s.dependency 'SwiftBase32', '~> 0.8.0'

  s.subspec 'scrypt' do |ss|
    ss.source_files = 'Sources/scrypt/**/*.{h,c}'
  end
end
