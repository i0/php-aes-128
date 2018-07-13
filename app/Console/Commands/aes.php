<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Classes\AES as AESCipher;

class aes extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'aes';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $aes = new AESCipher;
        $result = $aes->main();
        dd($result);
    }
}
