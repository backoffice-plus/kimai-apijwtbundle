<?php
namespace KimaiPlugin\ApiJwtBundle\DependencyInjection;

use App\Plugin\AbstractPluginExtension;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

use Symfony\Component\Yaml\Parser;

class ApiJwtExtension extends AbstractPluginExtension implements PrependExtensionInterface
{
    /**
     * @param array<string, mixed> $configs
     * @param ContainerBuilder $container
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $this->registerBundleConfiguration($container, $config);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }

    public function prepend(ContainerBuilder $container): void
    {
        $yamlParser = new Parser();

        //security
//        if (false === $data = file_get_contents(__DIR__ . '/../Resources/config/security.yaml')) {
//            throw new \Exception('Could not read security configuration');
//        }
//        $container->prependExtensionConfig('security', $yamlParser->parse($data)['security']);

        //nelmio_cors
        if (false === $data = file_get_contents(__DIR__ . '/../Resources/config/nelmio_cors.yaml')) {
            throw new \Exception('Could not read nelmio_cors configuration');
        }
        $container->prependExtensionConfig('nelmio_cors', $yamlParser->parse($data)['nelmio_cors']);

    }
}
