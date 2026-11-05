<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Attribute\\Route;

#[Route('/api/orders')]
class OrderController extends AbstractController
{
    #[Route('', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): Response
    {
        $order = new Order($request->toArray());
        $em->persist($order);
        $em->flush();
        return $this->json($order);
    }

    #[IsGranted('ROLE_USER')]
    #[Route('/{id}', methods: ['GET'])]
    public function show(int $id, OrderRepository $orders): Response
    {
        return $this->json($orders->find($id));
    }
}
