<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Attribute\\Route;

#[Route('/api/orders')]
#[IsGranted('ROLE_USER')]
class OrderController extends AbstractController
{
    #[Route('/{id}', methods: ['DELETE'])]
    public function remove(Order $order, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('DELETE', $order);
        $em->remove($order);
        $em->flush();
        return new Response(null, 204);
    }
}
