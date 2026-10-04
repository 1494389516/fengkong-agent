import unittest
from agent.graph_algorithms import graph_algorithm
class GraphBatch(unittest.TestCase):
    def test_equivalence(self):
        rows=[('e'+str(i),'u'+str(i%5),'d'+str(i%3),'g','ip',100,100) for i in range(20)]
        targets=[('d0','g'),('d1','g'),('d2','g'),('absent','g')]
        for name in ('community_v1','temporal_community_v1'):
            a=graph_algorithm(name)
            self.assertEqual(a.compute_many(rows,targets,as_of=101),
                             {t:a.compute(rows,*t,as_of=101) for t in targets})
if __name__=='__main__':unittest.main()
