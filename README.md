# Tapyrus ZKP

WIP

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'tapyrus-zkp'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install tapyrus-zkp

### Build tapyrus secp256k1

`tapyrus-zkp` requires Tapyrus's [secp256k1](https://github.com/chaintope/secp256k1).

    $ git submodule update --init --recursive
    $ cd depends/secp256k1-zkp
    $ ./autogen.sh
    $ ./configure --enable-module-ecdh --enable-module-generator --enable-module-recovery --enable-experimental  --enable-module-commitment  --enable-module-rangeproof --enable-module-bulletproof --enable-module-schnorrsig --enable-module-aggsig --disable-benchmark
    $ make -j"$(($(nproc)+1))" 

As a result, the `libsecp256k1.so` library will be generated under the `.libs` folder.

### Set environment variable

You need to set the path of `libsecp256k1.so` to the environment variable `LIBSECP256K1-ZKP`.

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/secp256k1-zkp. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/[USERNAME]/secp256k1-zkp/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Secp256k1::Zkp project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/secp256k1-zkp/blob/master/CODE_OF_CONDUCT.md).
