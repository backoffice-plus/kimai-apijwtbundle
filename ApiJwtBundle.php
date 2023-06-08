<?php

namespace KimaiPlugin\ApiJwtBundle;

use App\Plugin\PluginInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class ApiJwtBundle extends Bundle implements PluginInterface
{
//    public function loadExtension(array $config, ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder): void
//    {
//        // load an XML, PHP or Yaml file
//        $containerConfigurator->import('./Resources/config/nelmio_cors.yaml');
//        $containerConfigurator->import('./Resources/config/security.yaml');
//
//        throw new \Exception("Hallo loadExtension");
//    }
}
