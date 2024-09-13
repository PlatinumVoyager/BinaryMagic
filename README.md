# BinaryMagic
<img src="https://github.com/PlatinumVoyager/BinaryMagic/assets/116006542/3fbfead0-5b42-4c41-94fb-ec2bb8bda1f8" height=220 width=220/>

</br>
</br>

A bare bones ELF32/ELF64 bit Goblin binary executable parser written in Rust.

## Setup
To setup **BinaryMagic** invoke the following command:

```git clone https://github.com/PlatinumVoyager/BinaryMagic.git ; cd BinaryMagic ; cargo build && sudo cp target/debug/binarymagic /usr/bin && rm -r target && cd $HOME ; binarymagic```

## Usage
Basic use example: `binarymagic <TARGET> <ARGUMENTS>`

## Information
By default if no arguments are supplied to **BinaryMagic** it will display a blob of text containing usage information.

![image](https://github.com/PlatinumVoyager/BinaryMagic/assets/116006542/ada2dd4c-383e-400d-898a-3dd2648c17ec)


## Preview
Execute: `binarymagic /usr/bin/ls --sections`
<br/>

![image](https://github.com/PlatinumVoyager/BinaryMagic/assets/116006542/adc031c3-b191-454d-a37e-f1c0d1813af0)

_CORRECTION_: Abbreviations for bytes within the context of the displayed image above is incorrect. Integral values should have been divided by 8 to obtain the correct values. As the current display is set to the basis of bits, not bytes. It should be listed as Kb (kilo bits), Mb (Mega bits), etc. Not as KB (Kilo Bytes) = "bytes" (Ex: 2 Kb (2952 bytes) => 2 Kb (2952 bits) || 2 Kb ([2952 / 8] bytes))
